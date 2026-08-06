.PHONY: certs build up down clean logs

certs:
	mkdir -p haproxy/certs
	openssl req -x509 -newkey ec \
	  -pkeyopt ec_paramgen_curve:P-256 \
	  -keyout haproxy/certs/key.pem \
	  -out    haproxy/certs/cert.pem \
	  -days 365 -nodes \
	  -subj "/CN=hofmann-demo" \
	  -addext "subjectAltName=DNS:localhost,DNS:hofmann-demo,IP:127.0.0.1"
	cat haproxy/certs/cert.pem haproxy/certs/key.pem > haproxy/certs/demo.pem
	rm haproxy/certs/key.pem haproxy/certs/cert.pem

build:
	docker compose build

# Generates throwaway key material into .env if it is not already present, so `make up` works
# out of the box now that config.yml carries no committed fallbacks. .env is gitignored, and the
# keys persist across restarts of this demo so registrations survive `make down && make up`.
.env:
	@echo "Generating throwaway demo keys into .env (gitignored, not for production)"
	@{ \
	  echo "SERVER_KEY_SEED_HEX=$$(openssl rand -hex 32)"; \
	  echo "OPRF_SEED_HEX=$$(openssl rand -hex 32)"; \
	  echo "OPRF_MASTER_KEY_HEX=$$(openssl rand -hex 32)"; \
	  echo "JWT_SECRET_HEX=$$(openssl rand -hex 32)"; \
	} > .env

up: certs .env
	docker compose up -d

down:
	docker compose down

clean:
	docker compose down -v
	rm -rf haproxy/certs/

logs:
	docker compose logs -f
