from __future__ import print_function

import os
import sys, logging
import json
import re
import mechanize
import boto3

mechlog = logging.getLogger("mechanize")
mechlog.addHandler(logging.StreamHandler(sys.stdout))

if os.getenv('DEBUG') != None:
    logging.basicConfig(level=logging.DEBUG)
    mechlog.setLevel(logging.DEBUG)

confirm_url = re.compile("https://.*\.(acm-)?certificates.amazon.com/approvals\?[A-Za-z0-9=&-]+")
approval_text = re.compile("You have\s*<[^>]*>APPROVED<[^>]*>\s*this validation request", re.DOTALL)

domain_re = re.compile(".*<[^>]*>\s*Domain name\s*<[^>]*>[^<]*<[^>]*>\s*([^\s<]*)\s*<[^>]*>", re.DOTALL)
accountid_re = re.compile(".*<[^>]*>\s*AWS Account number\s*<[^>]*>[^<]*<[^>]*>\s*([^\s<]*)\s*<[^>]*>", re.DOTALL)
region_re = re.compile(".*<[^>]*>\s*AWS Region\s*<[^>]*>[^<]*<[^>]*>\s*([^\s<]*)\s*<[^>]*>", re.DOTALL)
certid_re = re.compile(".*<[^>]*>\s*Certificate Identifier\s*<[^>]*>[^<]*<[^>]*>\s*[^\s<]*certificate\/([^\s<]+)\s*<[^>]*>", re.DOTALL)

def panic(msg):
    raise Exception(msg)

def validate(event, context):
    msg = json.loads(event['Records'][0]['Sns']['Message'])
    match = confirm_url.search(msg['content'])

    # Ignore emails that don't match the certificate confirm URL
    if not match:
        logging.info("This is not a confirmation email, exiting.")
        return

    url = match.group(0)
    logging.info("CONFIRMATION URL: %s" % url)

    br = mechanize.Browser()
    br.set_handle_robots(False)

    # Fetch approval page
    logging.debug("OPENING CONFIRMATION URL")
    response = br.open(url)
    logging.debug("OPENED CONFIRMATION URL")
    content = response.get_data()

    # Extract confirmation page details
    domain, account_id, region, cert_id = [regex.match(content).group(1)
        if regex.match(content) else panic("Couldn't parse confirmation page!")
        for regex in (domain_re, accountid_re, region_re, certid_re)]

    # Remove dashes from account_id
    account_id = account_id.translate(None, '-')

    # Always log what we're confirming
    print("Validation URL: '%s'" % url)
    print("Domain: '%s'" % domain)
    print("Account ID: '%s'" % account_id)
    print("Region: '%s'" % region)
    print("Certificate ID: '%s'" % cert_id)

    # Check if the cert is pending validation
    acm = boto3.client('acm', region_name=region)
    cert = acm.describe_certificate(CertificateArn="arn:aws:acm:%s:%s:certificate/%s"
        % (region, account_id, cert_id))
    logging.debug(cert)

    if cert['Certificate']['Status'] != 'PENDING_VALIDATION':
        panic("Confirmation certificate is not pending validation!")

    # It's the first and only form on the page
    # Could we match on action="/approvals"?
    br.select_form(nr=0)
    logging.info("SUBMITTING CONFIRMATION FORM")

    # Get the submit button for "I Approve"
    submit_button = -1
    for i, control in enumerate(br.forms()[0].controls):
        if control.type == 'submit' and control.value == 'I Approve':
            submit_button = i

    if submit_button != -1:
        response = br.submit(nr=0)
        logging.info("SUBMITTED CONFIRMATION FORM")
        content = response.get_data()
    else:
        logging.error(content)
        panic("No approval submit button found!")

    match = approval_text.search(content)
    if match:
        print("Certificate for %s approved!" % domain)
    else:
        logging.error(content)
        panic("No confirmation of certificate approval!")
