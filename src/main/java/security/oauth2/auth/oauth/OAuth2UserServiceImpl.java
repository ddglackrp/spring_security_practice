package security.oauth2.auth.oauth;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import security.oauth2.auth.oauth.oauthResponse.OAuth2Response;
import security.oauth2.auth.domain.Member;
import security.oauth2.auth.oauth.oauthResponse.NaverResponse;
import security.oauth2.auth.repository.MemberRepository;

import java.util.Optional;

@Service
@AllArgsConstructor
@Slf4j
public class OAuth2UserServiceImpl extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        log.info("oauth user = {}",oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        OAuth2Response oAuth2Response = null;

        if(registrationId.equals("naver")){
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();

        Optional<Member> memberOptional = memberRepository.findByUsername(username);

        if(memberOptional.isPresent()){
            Member member = memberOptional.get();

            return new OAuth2UserImpl(member);
        }

        Member member = new Member(username, username, oAuth2Response.getEmail(), "ROLE_USER");

        memberRepository.save(member);

        return new OAuth2UserImpl(member);

    }
}
