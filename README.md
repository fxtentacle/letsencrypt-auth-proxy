# Let's Encrypt Auth Proxy

The purpose of this little tool is to securely access 
internal unsecured HTTP services over the internet.

- single executable
- no root or installation necessary
- HTTPS with Let's Encrypt certificate
- HTTP Basic auth (inside the HTTPS tunnel)
- Proxy to insecure http://127.0.0.1 service

## Example: Private Google Colab Clone
Compile this tool:
```bash
go build -o letsencrypt_auth_proxy
```
Spawn my colab on OVH imitation docker image:
```bash
mkdir ~/jupyter-workspace
docker run -d --rm -v ~/jupyter-workspace:/workspace \
  -e JOB_URL_SCHEME=https -e JOB_ID=1 -e JOB_HOST=localhost \
  -p 127.0.0.1:8080:8080 \
  fxtentacle/ovh-colab-sagemaker-compatibility-mode
```
Run the secure proxy:
```bash
mkdir ~/auth-proxy-ssl-cache
./letsencrypt_auth_proxy -d domain.example.com \
  -c ~/auth-proxy-ssl-cache -e email.for.letsencrypt \
  -u SECRET_USER -p SECRET_PASSWORD \ 
  -t "http://127.0.0.1:8080/"
```
And now the Jupyter notebook inside that docker image
is accessible on the public internet through HTTPS
and secured with your username and password.
