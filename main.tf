resource "aws_iam_user" "this" {
  count = var.create_user ? 1 : 0

  name          = var.name
  path          = var.path
  force_destroy = var.force_destroy
}

resource "aws_iam_user_login_profile" "this" {
  count = var.create_user && var.create_iam_user_login_profile ? 1 : 0

  user                    = aws_iam_user.this[0].name
  pgp_key                 = var.pgp_key
  password_length         = var.password_length
  password_reset_required = var.password_reset_required
}

resource "aws_iam_access_key" "this" {
  count = var.create_user && var.create_iam_access_key ? 1 : 0

  user    = aws_iam_user.this[0].name
  pgp_key = var.pgp_key
}

resource "aws_iam_user_ssh_key" "this" {
  count      = var.create_user && var.ssh_key != "" ? 1 : 0
  encoding   = "SSH"
  public_key = var.ssh_key
  username   = aws_iam_user.this[0].name
}

resource "aws_iam_user_policy" "this" {
  count = length(var.roles_to_assume) > 0 ? 1 : 0

  user   = aws_iam_user.this[0].name
  name   = "${aws_iam_user.this[0].name}_policy"
  policy = data.template_file.this[0].rendered
}

data "template_file" "this" {
  count    = length(var.roles_to_assume) > 0 ? 1 : 0
  template = file("${path.module}/policies/policy.json")

  vars = {
    roles = jsonencode(var.roles_to_assume)
  }
}

resource "aws_iam_policy_attachment" "this" {
  count      = var.create_user && var.enable_mfa ? 1 : 0
  name       = "mfa-policy-attachment"
  users      = [aws_iam_user.this[0].name]
  policy_arn = aws_iam_policy.mfa_policy[0].arn
}

resource "aws_iam_policy" "mfa_policy" {
  count = var.create_user && var.enable_mfa ? 1 : 0

  name   = "${aws_iam_user.this[0].name}_mfa_policy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAllUsersToListAccounts",
            "Effect": "Allow",
            "Action": [
                "iam:ListAccountAliases",
                "iam:ListUsers",
                "iam:ListVirtualMFADevices",
                "iam:GetAccountPasswordPolicy",
                "iam:GetAccountSummary"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowIndividualUserToSeeAndManageOnlyTheirOwnAccountInformation",
            "Effect": "Allow",
            "Action": [
                "iam:ChangePassword",
                "iam:CreateAccessKey",
                "iam:CreateLoginProfile",
                "iam:DeleteAccessKey",
                "iam:DeleteLoginProfile",
                "iam:GetLoginProfile",
                "iam:ListAccessKeys",
                "iam:UpdateAccessKey",
                "iam:UpdateLoginProfile",
                "iam:ListSigningCertificates",
                "iam:DeleteSigningCertificate",
                "iam:UpdateSigningCertificate",
                "iam:UploadSigningCertificate",
                "iam:ListSSHPublicKeys",
                "iam:GetSSHPublicKey",
                "iam:DeleteSSHPublicKey",
                "iam:UpdateSSHPublicKey",
                "iam:UploadSSHPublicKey"
            ],
            "Resource": "arn:aws:iam::*:user/$${aws:username}"
        },
        {
            "Sid": "AllowIndividualUserToListOnlyTheirOwnMFA",
            "Effect": "Allow",
            "Action": [
                "iam:ListMFADevices"
            ],
            "Resource": [
                "arn:aws:iam::*:mfa/*",
                "arn:aws:iam::*:user/$${aws:username}"
            ]
        },
        {
            "Sid": "AllowIndividualUserToManageTheirOwnMFA",
            "Effect": "Allow",
            "Action": [
                "iam:CreateVirtualMFADevice",
                "iam:DeleteVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:ResyncMFADevice"
            ],
            "Resource": [
                "arn:aws:iam::*:mfa/$${aws:username}",
                "arn:aws:iam::*:user/$${aws:username}"
            ]
        },
        {
            "Sid": "AllowIndividualUserToDeactivateOnlyTheirOwnMFAOnlyWhenUsingMFA",
            "Effect": "Allow",
            "Action": [
                "iam:DeactivateMFADevice"
            ],
            "Resource": [
                "arn:aws:iam::*:mfa/$${aws:username}",
                "arn:aws:iam::*:user/$${aws:username}"
            ],
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        },
        {
            "Sid": "BlockMostAccessUnlessSignedInWithMFA",
            "Effect": "Deny",
            "NotAction": [
                "iam:CreateVirtualMFADevice",
                "iam:DeleteVirtualMFADevice",
                "iam:ListVirtualMFADevices",
                "iam:EnableMFADevice",
                "iam:ResyncMFADevice",
                "iam:ListAccountAliases",
                "iam:ListUsers",
                "iam:ListSSHPublicKeys",
                "iam:ListAccessKeys",
                "iam:ListServiceSpecificCredentials",
                "iam:ListMFADevices",
                "iam:GetAccountSummary",
                "sts:GetSessionToken"
            ],
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        }
    ]
}
EOF

}

