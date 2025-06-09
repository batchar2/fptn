## Grafana

Grafana is used for monitoring server activity, including traffic amount and active users.

<img src="images/grafana-1.jpg" alt="Grafana"/>

<img src="images/grafana-2.jpg" alt="Grafana"/>

#### To set it up:

1. **Clone the repository:**

```bash
git clone https://github.com/batchar2/fptn.git
```

2. **Navigate to the Grafana configuration folder:**

```bash
cd sysadmin-tools/grafana
```

3. **Copy and configure the environment file:**
    - Copy the `.env.demo` file to `.env`:

      ```bash
      cp .env.demo .env
      ```

    - Open the `.env` file in a text editor and fill in all required fields.
    - Set your piblic ip for `FPTN_HOST` and your fptn port for `FPTN_PORT`
    - Pay special attention to the `PROMETHEUS_SECRET_ACCESS_KEY` parameter:
        - This value **must match** the access key defined in your `fptn-server` config at `/etc/fptn/server.conf`.
        - Use a **secure, random string** of **at least 30 characters** for this value.

4. **Run Docker Compose:**
   - Need install docker. To install it on ubuntu use [this docs](https://docs.docker.com/engine/install/ubuntu/)
   - Start Grafana and its dependencies using Docker Compose:
   
        ```bash
        docker compose down && docker compose up -d
        ```
5. **Access Grafana:**
    - Open your browser and navigate to the Grafana interface using the selected port (**3000 by default**).
    - Log in using the default credentials: `admin` / `admin`.
    - After logging in, Grafana will prompt you to change the default password — **do it immediately and avoid using default credentials going forward!**

#### Notes:

Ensure that all parameters in the .env file are correctly configured before starting the services.
The `PROMETHEUS_SECRET_ACCESS_KEY` parameter must be consistent with the key used in fptn-server to allow proper access to metrics.


#### 🐳 Building and Running the Docker Image (Optional)

To build the image:

```bash
docker compose build -f docker-compose.build.yml
```

To run the services:

```bash
docker compose build -f docker-compose.build.yml up -d
```

To stop the services:

```bash
docker compose build -f docker-compose.build.yml down
```
