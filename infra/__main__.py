import base64

import pulumi
from pulumi import Config, Output
from pulumi_azure_native import app, compute, insights, network, operationalinsights, resources


config = Config()
azure_config = Config("azure-native")

location = azure_config.get("location") or "westeurope"
project_name = config.get("projectName") or "ddos-bil"

client_rg_name = config.get("clientResourceGroupName") or f"rg-{project_name}-client"
attacker_rg_name = config.get("attackerResourceGroupName") or f"rg-{project_name}-attacker"

log_retention_days = config.get_int("logAnalyticsRetentionDays") or 30
test_client_image = config.require("testClientImage")
reverse_proxy_image = config.require("reverseProxyImage")
test_client_cpu = config.get_float("testClientCpu") or 0.5
test_client_memory = config.get("testClientMemory") or "1Gi"
reverse_proxy_cpu = config.get_float("reverseProxyCpu") or 0.5
reverse_proxy_memory = config.get("reverseProxyMemory") or "1Gi"
min_replicas = config.get_int("minReplicas") or 1
max_replicas = config.get_int("maxReplicas") or 3
enable_diagnostic_settings = config.get_bool("enableDiagnosticSettings") or False

container_registry_server = config.get("containerRegistryServer")
container_registry_username = config.get("containerRegistryUsername")
container_registry_password = config.get_secret("containerRegistryPassword")

attacker_admin_username = config.get("attackerAdminUsername") or "azureuser"
attacker_vm_size = config.get("attackerVmSize") or "Standard_D2s_v5"
attacker_public_ip_count = config.get_int("attackerPublicIpCount") or 8
attacker_allowed_ssh_cidr = config.require("attackerAllowedSshCidr")
attacker_ssh_public_key = config.require("attackerSshPublicKey")


def reject_placeholder(name: str, value: str) -> None:
    if value.startswith("CHANGE_ME") or value == "nginx:stable-alpine":
        raise ValueError(f"{name} must be set to a real deployable image or value before deployment")


reject_placeholder("testClientImage", test_client_image)
reject_placeholder("reverseProxyImage", reverse_proxy_image)
reject_placeholder("attackerSshPublicKey", attacker_ssh_public_key)

if attacker_allowed_ssh_cidr == "0.0.0.0/0":
    raise ValueError("attackerAllowedSshCidr must be restricted before deployment, for example YOUR_PUBLIC_IP/32")

if container_registry_server and (not container_registry_username or container_registry_password is None):
    raise ValueError("containerRegistryServer requires containerRegistryUsername and containerRegistryPassword")


def container_app_configuration(ingress: app.IngressArgs) -> app.ConfigurationArgs:
    if not container_registry_server:
        return app.ConfigurationArgs(ingress=ingress)

    return app.ConfigurationArgs(
        ingress=ingress,
        registries=[
            app.RegistryCredentialsArgs(
                server=container_registry_server,
                username=container_registry_username,
                password_secret_ref="registry-password",
            )
        ],
        secrets=[app.SecretArgs(name="registry-password", value=container_registry_password)],
    )


client_rg = resources.ResourceGroup(
    "client-rg",
    resource_group_name=client_rg_name,
    location=location,
)

attacker_rg = resources.ResourceGroup(
    "attacker-rg",
    resource_group_name=attacker_rg_name,
    location=location,
)

workspace = operationalinsights.Workspace(
    "client-law",
    resource_group_name=client_rg.name,
    workspace_name=f"law-{project_name}-client",
    location=client_rg.location,
    retention_in_days=log_retention_days,
    sku=operationalinsights.WorkspaceSkuArgs(name="PerGB2018"),
)

workspace_keys = Output.all(client_rg.name, workspace.name).apply(
    lambda args: operationalinsights.get_shared_keys(
        resource_group_name=args[0],
        workspace_name=args[1],
    )
)

managed_environment = app.ManagedEnvironment(
    "client-container-apps-env",
    environment_name=f"cae-{project_name}-client",
    resource_group_name=client_rg.name,
    location=client_rg.location,
    app_logs_configuration=app.AppLogsConfigurationArgs(
        destination="log-analytics",
        log_analytics_configuration=app.LogAnalyticsConfigurationArgs(
            customer_id=workspace.customer_id,
            shared_key=workspace_keys.apply(lambda keys: keys.primary_shared_key),
        ),
    ),
)

test_client_app = app.ContainerApp(
    "test-client-container-app",
    container_app_name=f"ca-{project_name}-test-client",
    resource_group_name=client_rg.name,
    location=client_rg.location,
    managed_environment_id=managed_environment.id,
    configuration=container_app_configuration(
        app.IngressArgs(
            external=False,
            target_port=8000,
            transport="auto",
        ),
    ),
    template=app.TemplateArgs(
        containers=[
            app.ContainerArgs(
                name="test-client",
                image=test_client_image,
                env=[
                    app.EnvironmentVarArgs(name="LONG_RESPONSE_DELAY_MS", value="500"),
                    app.EnvironmentVarArgs(name="LONG_RESPONSE_MEMORY_MB", value="0"),
                    app.EnvironmentVarArgs(name="DOWNLOAD_FILE_SIZE_KB", value="256"),
                    app.EnvironmentVarArgs(name="DOWNLOAD_CHUNK_KB", value="64"),
                ],
                probes=[
                    app.ContainerAppProbeArgs(
                        type="Liveness",
                        http_get=app.ContainerAppProbeHttpGetArgs(path="/healthcheck", port=8000),
                        initial_delay_seconds=10,
                        period_seconds=10,
                    ),
                    app.ContainerAppProbeArgs(
                        type="Readiness",
                        http_get=app.ContainerAppProbeHttpGetArgs(path="/healthcheck", port=8000),
                        initial_delay_seconds=5,
                        period_seconds=10,
                    ),
                ],
                resources=app.ContainerResourcesArgs(cpu=test_client_cpu, memory=test_client_memory),
            )
        ],
        scale=app.ScaleArgs(min_replicas=min_replicas, max_replicas=max_replicas),
    ),
)

reverse_proxy_app = app.ContainerApp(
    "reverse-proxy-container-app",
    container_app_name=f"ca-{project_name}-reverse-proxy",
    resource_group_name=client_rg.name,
    location=client_rg.location,
    managed_environment_id=managed_environment.id,
    configuration=container_app_configuration(
        app.IngressArgs(
            external=True,
            target_port=8080,
            transport="auto",
        ),
    ),
    template=app.TemplateArgs(
        containers=[
            app.ContainerArgs(
                name="reverse-proxy",
                image=reverse_proxy_image,
                env=[
                    app.EnvironmentVarArgs(
                        name="TARGET_BASE_URL",
                        value=test_client_app.configuration.apply(
                            lambda c: f"https://{c.ingress.fqdn}" if c and c.ingress else ""
                        ),
                    ),
                    app.EnvironmentVarArgs(name="TRUST_SIMULATED_IP", value="true"),
                    app.EnvironmentVarArgs(name="RATE_LIMIT_REQUESTS", value="20"),
                    app.EnvironmentVarArgs(name="RATE_LIMIT_WINDOW_SECONDS", value="1"),
                    app.EnvironmentVarArgs(name="BLOCK_DURATION_SECONDS", value="30"),
                    app.EnvironmentVarArgs(name="REQUEST_TIMEOUT_SECONDS", value="30"),
                ],
                probes=[
                    app.ContainerAppProbeArgs(
                        type="Liveness",
                        http_get=app.ContainerAppProbeHttpGetArgs(path="/proxy_healthcheck", port=8080),
                        initial_delay_seconds=10,
                        period_seconds=10,
                    ),
                    app.ContainerAppProbeArgs(
                        type="Readiness",
                        http_get=app.ContainerAppProbeHttpGetArgs(path="/proxy_healthcheck", port=8080),
                        initial_delay_seconds=5,
                        period_seconds=10,
                    ),
                ],
                resources=app.ContainerResourcesArgs(cpu=reverse_proxy_cpu, memory=reverse_proxy_memory),
            )
        ],
        scale=app.ScaleArgs(min_replicas=min_replicas, max_replicas=max_replicas),
    ),
)

attacker_vnet = network.VirtualNetwork(
    "attacker-vnet",
    resource_group_name=attacker_rg.name,
    virtual_network_name=f"vnet-{project_name}-attacker",
    location=attacker_rg.location,
    address_space=network.AddressSpaceArgs(address_prefixes=["10.40.0.0/16"]),
)

attacker_nsg = network.NetworkSecurityGroup(
    "attacker-nsg",
    resource_group_name=attacker_rg.name,
    network_security_group_name=f"nsg-{project_name}-attacker",
    location=attacker_rg.location,
    security_rules=[
        network.SecurityRuleArgs(
            name="AllowSsh",
            priority=100,
            direction="Inbound",
            access="Allow",
            protocol="Tcp",
            source_port_range="*",
            destination_port_range="22",
            source_address_prefix=attacker_allowed_ssh_cidr,
            destination_address_prefix="*",
        )
    ],
)

attacker_subnet = network.Subnet(
    "attacker-subnet",
    resource_group_name=attacker_rg.name,
    virtual_network_name=attacker_vnet.name,
    subnet_name="snet-attacker",
    address_prefix="10.40.1.0/24",
    network_security_group=network.NetworkSecurityGroupArgs(id=attacker_nsg.id),
)

attacker_public_ips = [
    network.PublicIPAddress(
        f"attacker-public-ip-{index + 1}",
        resource_group_name=attacker_rg.name,
        public_ip_address_name=f"pip-{project_name}-attacker-{index + 1}",
        location=attacker_rg.location,
        public_ip_allocation_method="Static",
        sku=network.PublicIPAddressSkuArgs(name="Standard"),
    )
    for index in range(attacker_public_ip_count)
]

ip_configurations = [
    network.NetworkInterfaceIPConfigurationArgs(
        name=f"ipconfig-{index + 1}",
        primary=index == 0,
        private_ip_allocation_method="Dynamic",
        subnet=network.SubnetArgs(id=attacker_subnet.id),
        public_ip_address=network.PublicIPAddressArgs(id=public_ip.id),
    )
    for index, public_ip in enumerate(attacker_public_ips)
]

attacker_nic = network.NetworkInterface(
    "attacker-nic",
    resource_group_name=attacker_rg.name,
    network_interface_name=f"nic-{project_name}-attacker",
    location=attacker_rg.location,
    ip_configurations=ip_configurations,
)

cloud_init = f"""#cloud-config
package_update: true
packages:
  - ca-certificates
  - curl
  - git
  - gnupg
  - python3-pip
  - python3-venv
runcmd:
  - curl -fsSL https://get.docker.com | sh
  - usermod -aG docker {attacker_admin_username}
"""

attacker_vm = compute.VirtualMachine(
    "attacker-vm",
    resource_group_name=attacker_rg.name,
    vm_name=f"vm-{project_name}-attacker",
    location=attacker_rg.location,
    hardware_profile=compute.HardwareProfileArgs(vm_size=attacker_vm_size),
    os_profile=compute.OSProfileArgs(
        computer_name=f"vm-{project_name}-attacker",
        admin_username=attacker_admin_username,
        custom_data=base64.b64encode(cloud_init.encode("utf-8")).decode("utf-8"),
        linux_configuration=compute.LinuxConfigurationArgs(
            disable_password_authentication=True,
            ssh=compute.SshConfigurationArgs(
                public_keys=[
                    compute.SshPublicKeyArgs(
                        path=f"/home/{attacker_admin_username}/.ssh/authorized_keys",
                        key_data=attacker_ssh_public_key,
                    )
                ]
            ),
        ),
    ),
    network_profile=compute.NetworkProfileArgs(
        network_interfaces=[compute.NetworkInterfaceReferenceArgs(id=attacker_nic.id, primary=True)]
    ),
    storage_profile=compute.StorageProfileArgs(
        image_reference=compute.ImageReferenceArgs(
            publisher="Canonical",
            offer="0001-com-ubuntu-server-jammy",
            sku="22_04-lts-gen2",
            version="latest",
        ),
        os_disk=compute.OSDiskArgs(
            create_option="FromImage",
            managed_disk=compute.ManagedDiskParametersArgs(storage_account_type="Premium_LRS"),
            disk_size_gb=64,
        ),
    ),
)

diagnostic_workspace_id = workspace.id

if enable_diagnostic_settings:
    insights.DiagnosticSetting(
        "test-client-diagnostics",
        name="send-to-log-analytics",
        resource_uri=test_client_app.id,
        workspace_id=diagnostic_workspace_id,
        logs=[insights.LogSettingsArgs(category_group="allLogs", enabled=True)],
        metrics=[insights.MetricSettingsArgs(category="AllMetrics", enabled=True)],
    )

    insights.DiagnosticSetting(
        "reverse-proxy-diagnostics",
        name="send-to-log-analytics",
        resource_uri=reverse_proxy_app.id,
        workspace_id=diagnostic_workspace_id,
        logs=[insights.LogSettingsArgs(category_group="allLogs", enabled=True)],
        metrics=[insights.MetricSettingsArgs(category="AllMetrics", enabled=True)],
    )

pulumi.export("clientResourceGroupName", client_rg.name)
pulumi.export("attackerResourceGroupName", attacker_rg.name)
pulumi.export("logAnalyticsWorkspaceName", workspace.name)
pulumi.export("containerAppsEnvironmentName", managed_environment.name)
pulumi.export("testClientContainerAppName", test_client_app.name)
pulumi.export("reverseProxyContainerAppName", reverse_proxy_app.name)
pulumi.export("reverseProxyFqdn", reverse_proxy_app.configuration.apply(lambda c: c.ingress.fqdn if c and c.ingress else None))
pulumi.export("attackerVmName", attacker_vm.name)
pulumi.export("attackerPublicIpAddresses", [public_ip.ip_address for public_ip in attacker_public_ips])
