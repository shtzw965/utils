openssl req -x509 -newkey rsa:2048 -keyout key.pem -out crt.pem -days 365 -nodes -subj '/CN=self'
