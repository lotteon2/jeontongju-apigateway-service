package com.jeontongju.gateway.filter;

import com.jeontongju.gateway.utils.CustomErrMessage;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import javax.crypto.SecretKey;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class OptionalAuthorizationHeaderFilter
    extends AbstractGatewayFilterFactory<OptionalAuthorizationHeaderFilter.Config> {

  private final String secret;

  public OptionalAuthorizationHeaderFilter(Environment env) {
    super(OptionalAuthorizationHeaderFilter.Config.class);
    this.secret = env.getProperty("jwt.secret");
  }

  @Override
  public GatewayFilter apply(Config config) {
    return ((exchange, chain) -> {
      log.info("OptionalAuthorizationHeaderFilter's apply executes");

      ServerHttpRequest request = exchange.getRequest();
      if (request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {

        log.info("[Authorization value]: " + request.getHeaders().get(HttpHeaders.AUTHORIZATION));
        if (request.getHeaders().get(HttpHeaders.AUTHORIZATION) == null) {
          //          return chain.filter(exchange);
          return onError(exchange, CustomErrMessage.NOT_VALID_JWT_TOKEN);
        }

        String jwtHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
        String jwt = jwtHeader.replace("Bearer ", "");

        byte[] keyBytes = Decoders.BASE64.decode(secret);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        try {
          Claims claims = checkValid(jwt, key); // 토큰 유효성 검사
          String username = claims.get("username", String.class);

          if (username == null) {
            return onError(exchange, CustomErrMessage.NOT_VALID_JWT_TOKEN);
          }

          String memberId = claims.get("memberId", String.class);
          String memberRole = claims.get("memberRole", String.class);
          exchange
              .getRequest()
              .mutate()
              .header("memberId", memberId)
              .header("memberRole", memberRole)
              .build();
        } catch (IllegalArgumentException e) {
          return onError(exchange, CustomErrMessage.WRONG_JWT_TOKEN);
        } catch (MalformedJwtException e) {
          return onError(exchange, CustomErrMessage.MALFORMED_JWT_TOKEN);
        } catch (ExpiredJwtException e) { // access-token 만료
          return onErrorByExpiration(exchange, CustomErrMessage.EXPIRED_JWT_TOKEN);
        } catch (SignatureException e) {
          return onError(exchange, CustomErrMessage.WRONG_JWT_SIGNATURE);
        }
      } else {
        log.info("[Non-Login OK]..");
        return chain.filter(exchange);
      }

      log.info("Successful Verifying Access-Permissions!");
      return chain.filter(exchange);
    });
  }

  private Claims checkValid(String jwt, SecretKey key)
      throws IllegalArgumentException, ExpiredJwtException, SignatureException {

    return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();
  }

  private Mono<Void> onErrorByExpiration(ServerWebExchange exchange, String error) {

    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(HttpStatus.valueOf(418));

    log.error(error);
    return response.setComplete();
  }

  private Mono<Void> onError(ServerWebExchange exchange, String error) {

    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(HttpStatus.UNAUTHORIZED);

    log.error(error);

    return response.setComplete();
  }

  @Data
  public static class Config {}
}
