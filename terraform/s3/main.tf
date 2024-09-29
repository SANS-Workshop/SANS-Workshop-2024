resource "aws_s3_bucket" "test" {
  bucket = "test"

  tags = {
    data_classification = "private"
    owner_email = "admin@mydomain.com"
  }
}

#resource "aws_s3_bucket_public_access_block" "test" {
#  bucket = aws_s3_bucket.test.id

#  block_public_acls   = false
#  block_public_policy = false
#}