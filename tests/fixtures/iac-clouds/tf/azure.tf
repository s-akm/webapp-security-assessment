# 架空の定義。名前と値はすべて架空

# 公開の可否を書いていないストレージアカウント（既定はプロバイダの版で違う）
resource "azurerm_storage_account" "uploads" {
  name                     = "exampleuploads"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_account" "private" {
  name                            = "exampleprivate"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "public_assets" {
  name                  = "assets"
  container_access_type = "blob"
}

resource "azurerm_network_security_rule" "ssh" {
  name                       = "ssh"
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "Tcp"
  source_address_prefix      = "*"
  destination_port_range     = "22"
}

# すべての IP アドレスから DB へ届く規則
resource "azurerm_mssql_firewall_rule" "all" {
  name             = "all"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_firewall_rule" "azure_services" {
  name             = "azure"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "office" {
  name             = "office"
  start_ip_address = "203.0.113.10"
  end_ip_address   = "203.0.113.10"
}
