package security.oauth2.auth.configuration;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import security.oauth2.auth.servletUtils.jwtUtils.JWTResponseUtils;
import security.oauth2.auth.filter.JWTAccessFilter;
import security.oauth2.auth.filter.JWTRefreshFilter;
import security.oauth2.auth.jwt.JWTUtils;
import security.oauth2.auth.filter.JWTLogoutFilter;
import security.oauth2.auth.oauth.OAuth2SuccessHandler;
import security.oauth2.auth.repository.RefreshTokenRepository;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfiguration {

    private final security.oauth2.auth.oauth.OAuth2UserServiceImpl OAuth2UserServiceImpl;

    private final OAuth2SuccessHandler OAuth2SuccessHandler;

    private final JWTUtils jwtUtil;

    private final RefreshTokenRepository refreshTokenRepository;

    private final JWTResponseUtils jwtResponseUtils;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//        http
//                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
//
//                    @Override
//                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
//
//                        CorsConfiguration configuration = new CorsConfiguration();
//
//                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
//                        configuration.setAllowedMethods(Collections.singletonList("*"));
//                        configuration.setAllowCredentials(true);
//                        configuration.setAllowedHeaders(Collections.singletonList("*"));
//                        configuration.setMaxAge(3600L);
//
//                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
//                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));
//
//                        return configuration;
//                    }
//                }));

        //csrf disable
        http
            .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable
        http
            .formLogin((auth) -> auth.disable());

        //HTTP Basic 인증 방식 disable
        http
            .httpBasic((auth) -> auth.disable());

        //JWTFilter 추가
        http
            .addFilterAfter(new JWTAccessFilter(jwtUtil, jwtResponseUtils), OAuth2LoginAuthenticationFilter.class)
            .addFilterAfter(new JWTRefreshFilter(jwtUtil, jwtResponseUtils), OAuth2LoginAuthenticationFilter.class)
            .addFilterBefore(new JWTLogoutFilter(jwtUtil, refreshTokenRepository, jwtResponseUtils), LogoutFilter.class);

        //oauth2
        http
            .oauth2Login((oauth2) -> oauth2
                    .loginPage("/login")
                    .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig.userService(OAuth2UserServiceImpl))
                    .successHandler(OAuth2SuccessHandler)
            );

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/reissue").permitAll()
                        .requestMatchers("my").hasRole("USER")
                        .anyRequest().authenticated());

        //세션 설정 : STATELESS
        http
                .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers("/favicon.ico")
                .requestMatchers("/error")
                .requestMatchers(toH2Console());
    }

}
