package security.oauth2.auth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import security.oauth2.auth.annotation.LoginMember;
import security.oauth2.auth.domain.Member;

@Controller
@Slf4j
public class MyController {

    @GetMapping("/my")
    @ResponseBody
    public String myAPI(@LoginMember Member member) {
        log.info("member = {}",member);
        log.info("home controller name = {}", member.getUsername());
        return "my route";
    }
}
