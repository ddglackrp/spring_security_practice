package security.oauth2.auth.resolver;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import security.oauth2.auth.annotation.LoginMember;
import security.oauth2.auth.domain.Member;
import security.oauth2.auth.jwt.JWTUtils;
import security.oauth2.auth.repository.MemberRepository;

@Component
@AllArgsConstructor
@Slf4j
public class CustomAuthenticationPrincipalArgumentResolver implements HandlerMethodArgumentResolver {

    private final JWTUtils jwtUtils;

    private final MemberRepository memberRepository;

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(LoginMember.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(isAuthenticationMember(authentication)){
            log.info("Authentication 객체가 없거나, 익명 사용자 입니다.");
            return null;
        }

        Member member = getMemberFromAuthentication(authentication);

        log.info("member name = {}",member.getUsername());

        return member;
    }

    private Member getMemberFromAuthentication(Authentication authentication) {
        // jwt token 추출
        String token = (String) authentication.getPrincipal();

        String username = jwtUtils.getEmail(token);

        return memberRepository.findByEmail(username).orElseThrow();
    }

    private boolean isAuthenticationMember(Authentication authentication) {
        return authentication == null || authentication instanceof AnonymousAuthenticationToken;
    }
}
