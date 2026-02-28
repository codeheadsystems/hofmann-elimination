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

up: certs
	docker compose up -d

down:
	docker compose down

clean:
	docker compose down -v
	rm -rf haproxy/certs/

logs:
	docker compose logs -f
