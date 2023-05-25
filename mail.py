import email


def decodeMail(filename):
    with open(filename, 'rb') as f:
        msg = email.message_from_binary_file(f)

    subject = msg.get('Subject')
    body = ''

    if msg.is_multipart():
        # If the message has multiple parts, iterate through them and append the body content
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain' or content_type == 'text/html':
                body += part.get_payload(decode=True).decode()
    else:
        # If the message has only one part, extract the body content directly
        body = msg.get_payload(decode=True).decode()

    subject = email.header.decode_header(subject)[0][0].decode('utf')
    return subject.strip(), body.strip()

