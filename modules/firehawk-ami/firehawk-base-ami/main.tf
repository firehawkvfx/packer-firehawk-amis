output "firehawk-amis" {
    value = file( "${path.module}/manifest.json" )
}