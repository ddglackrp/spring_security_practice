package security.oauth2.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import security.oauth2.auth.domain.RefreshToken;
import security.oauth2.auth.repository.RefreshTokenRepository;
import security.oauth2.auth.servletUtils.cookie.CookieUtils;
import security.oauth2.auth.jwt.JWTUtils;

import java.util.Date;

@Controller
@ResponseBody
@AllArgsConstructor
public class ReissueController {

    private final JWTUtils jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        String refresh = (String) request.getAttribute("refresh");

        String email = jwtUtil.getEmail(refresh);
        String role = jwtUtil.getRole(refresh);

        //make new JWT
        String newAccess = jwtUtil.createJwt("access", email, role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh", email, role, 86400000L);

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        refreshTokenRepository.deleteByToken(refresh);

        addRefreshEntity(email, newRefresh, 86400000L);

        //response
        response.setHeader("Authorization", "Bearer " + newAccess);

        response.addCookie(CookieUtils.createCookie("refresh", newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }

    private void addRefreshEntity(String email, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshToken refreshToken = new RefreshToken(email, refresh, date.toString());

        refreshTokenRepository.save(refreshToken);
    }
}