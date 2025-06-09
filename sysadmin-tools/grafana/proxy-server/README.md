### proxy-server

This service acts as a proxy for forwarding requests to the API of the `fptn-server`.

The reason for this is that the `fptn-server` uses a custom TLS handshake, which this proxy handles correctly.  
It also retrieves Prometheus metrics from the server and exposes them in a format that Prometheus can consume.

This service is built using Docker.  
Check the [manual](../README.md) for instructions on how to build it.
