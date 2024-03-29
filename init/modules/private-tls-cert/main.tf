# ---------------------------------------------------------------------------------------------------------------------
#  CREATE A CA CERTIFICATE
# ---------------------------------------------------------------------------------------------------------------------

locals {
  tls_locally_signed_cert = sensitive(tls_locally_signed_cert.cert.cert_pem)
  tls_private_key         = sensitive(tls_private_key.cert.private_key_pem)
  tls_self_signed_cert    = sensitive(tls_self_signed_cert.ca.cert_pem)
}

resource "tls_private_key" "ca" {
  algorithm   = var.private_key_algorithm
  ecdsa_curve = var.private_key_ecdsa_curve
  rsa_bits    = var.private_key_rsa_bits
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem   = sensitive(tls_private_key.ca.private_key_pem)
  is_ca_certificate = true

  validity_period_hours = var.validity_period_hours
  allowed_uses          = var.ca_allowed_uses

  subject {
    common_name  = var.ca_common_name
    organization = var.organization_name
  }
}
# Store the CA public key in a file.
resource "null_resource" "ca_public_key_file_path" {
  triggers = {
    always_run = timestamp() # Always run this since we dont know if this is a new vault and an old state file.  This could be better.  perhaps track an init var in the vault?
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = "echo 'set permissions init/modules/private-tls-cert' && echo '${local.tls_self_signed_cert}' > '${var.ca_public_key_file_path}' && chmod ${var.permissions} '${var.ca_public_key_file_path}' && chown ${var.cert_owner} '${var.ca_public_key_file_path}'"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# CREATE A TLS CERTIFICATE SIGNED USING THE CA CERTIFICATE
# ---------------------------------------------------------------------------------------------------------------------

resource "tls_private_key" "cert" {
  algorithm   = var.private_key_algorithm
  ecdsa_curve = var.private_key_ecdsa_curve
  rsa_bits    = var.private_key_rsa_bits
}
# Store the certificate's private key in a file.
resource "null_resource" "private_key_file_path" {
  triggers = {
    always_run = timestamp() # Always run this since we dont know if this is a new vault and an old state file.  This could be better.  perhaps track an init var in the vault?
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = "echo '${local.tls_private_key}' > '${var.private_key_file_path}' && chmod ${var.permissions} '${var.private_key_file_path}' && chown ${var.cert_owner} '${var.private_key_file_path}'"
  }
}

resource "tls_cert_request" "cert" {
  private_key_pem = tls_private_key.cert.private_key_pem

  dns_names    = var.dns_names
  ip_addresses = var.ip_addresses

  subject {
    common_name  = var.common_name
    organization = var.organization_name
  }
}

resource "tls_locally_signed_cert" "cert" {
  cert_request_pem = tls_cert_request.cert.cert_request_pem

  ca_private_key_pem = sensitive(tls_private_key.ca.private_key_pem)
  ca_cert_pem        = sensitive(tls_self_signed_cert.ca.cert_pem)

  validity_period_hours = var.validity_period_hours
  allowed_uses          = var.allowed_uses
}
# Store the certificate's public key in a file.
resource "null_resource" "public_key_file_path" {
  triggers = {
    always_run = timestamp() # Always run this since we dont know if this is a new vault and an old state file.  This could be better.  perhaps track an init var in the vault?
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = "echo '${local.tls_locally_signed_cert}' > '${var.public_key_file_path}' && chmod ${var.permissions} '${var.public_key_file_path}' && chown ${var.cert_owner} '${var.public_key_file_path}'"
  }
}
