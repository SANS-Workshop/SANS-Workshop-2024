resource "aws_db_instance" "my_db" {
  allocated_storage = 10
  engine            = "mysql"
  engine_version    = "5.7"
  instance_class    = "db.t3.micro"
  username          = "root"
  #password          = "my_super_secret_password"
  manage_master_user_password = true
  storage_encrypted = false
  #tags = {
  #  data_classification = "public"
  #  owner_email = "admin@mydomain.com"
  #}
}
