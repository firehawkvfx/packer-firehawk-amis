output "firehawk_ami_map" {
    value = file( "${path.module}/manifest.json" )
}