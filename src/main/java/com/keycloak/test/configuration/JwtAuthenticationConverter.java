package com.keycloak.test.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationConverter.class);

    @Value("${jwt.auth.converter.principle-attribute}")
    private String principleAttribute;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {

        logger.debug("Converting JWT: {}", jwt.getTokenValue());

        // Obtiene los roles
        Collection<GrantedAuthority> authorities = Stream
                .concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(), extractResourceRoles(jwt).stream())
                .toList();

        logger.debug("Extracted authorities: {}", authorities);

        // Crea el token de autenticación
        String principalClaim = getPrincipleClaimName(jwt);
        logger.debug("Principal claim extracted: {}", principalClaim);

        return new JwtAuthenticationToken(
                jwt,
                authorities,
                principalClaim
        );
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        logger.debug("Extracting resource roles from JWT");

        if (jwt.getClaim("resource_access") == null) {
            logger.debug("No 'resource_access' claim found in JWT.");
            return Set.of();
        }

        resourceAccess = jwt.getClaim("resource_access");
        logger.debug("Resource access: {}", resourceAccess);

        if (resourceAccess.get(resourceId) == null) {
            logger.debug("No resource found for resourceId: {}", resourceId);
            return Set.of();
        }

        resource = (Map<String, Object>) resourceAccess.get(resourceId);
        logger.debug("Resource data: {}", resource);

        resourceRoles = (Collection<String>) resource.get("roles");
        logger.debug("Resource roles: {}", resourceRoles);

        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

    private String getPrincipleClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (principleAttribute != null) {
            claimName = principleAttribute;
        }
        logger.debug("Principle claim name: {}", claimName);

        return jwt.getClaim(claimName);
    }
}
