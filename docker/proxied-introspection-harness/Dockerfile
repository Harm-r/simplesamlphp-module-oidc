# The image every container of the proxied introspection harness runs: SimpleSAMLphp with this module installed from
# the checkout. The containers mount the checkout over the installed copy, so a change to the module needs no
# rebuild; a change to its dependencies does. Built on the same base image as docker/Dockerfile; see "Build the
# SimpleSAMLphp base image" in docs/4-oidc-docker.md.
ARG SSP_IMAGE="ssp-base:v2.5.3.1"
FROM ${SSP_IMAGE}

ENV STAGINGCOMPOSERREPOS=oidc \
    COMPOSER_REQUIRE="simplesamlphp/simplesamlphp-module-oidc:@dev"
COPY . /var/simplesamlphp/staging-modules/oidc

# Dependency repository declarations do not propagate to the SSP root.
RUN git config --global --add safe.directory '*' \
    && /opt/simplesaml/staging-install.sh \
    && composer --working-dir=/var/simplesamlphp config repositories.openid-ml-dsa vcs https://github.com/Harm-r/openid.git \
    && /opt/simplesaml/module-setup.sh

# Installed once, here: a container starting from this image runs no Composer.
ENV STAGINGCOMPOSERREPOS="" \
    COMPOSER_REQUIRE=""
