package security.oauth2.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;
import security.oauth2.auth.jwt.JWTUtils;
import security.oauth2.auth.repository.RefreshTokenRepository;
import security.oauth2.auth.servletUtils.jwtUtils.JWTResponseUtils;
import security.oauth2.auth.servletUtils.cookie.CookieUtils;

import java.io.IOException;

@AllArgsConstructor
public class JWTLogoutFilter extends GenericFilterBean {

    private final JWTUtils jwtUtil;
    private final RefreshTokenRepository refreshRepository;
    private final JWTResponseUtils jwtResponseUtils;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        if (!isUrlLogout(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!isHttpMethodPost(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String refresh = CookieUtils.checkRefreshTokenInCookie(request);

        if (refresh == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        if (!jwtResponseUtils.isTokenInDB(response, refresh)) {
            return;
        }

        if (jwtResponseUtils.isTokenExpired(response, refresh)) {
            return;
        }

        if (!jwtResponseUtils.checkTokenType(response, refresh, "refresh")) {
            return;
        }

        refreshRepository.deleteByToken(refresh);

        CookieUtils.clearCookie(response);
    }

    private boolean isHttpMethodPost(String requestMethod) {
        return requestMethod.equals("POST");
    }

    private boolean isUrlLogout(String requestUri) {
        return requestUri.matches("^\\/logout$");
    }

}