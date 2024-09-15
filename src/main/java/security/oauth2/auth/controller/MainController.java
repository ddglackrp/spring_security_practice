package security.oauth2.auth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
public class MainController {

    @GetMapping("/")
    @ResponseBody
    public String mainAPI() {
        return "main route";
    }
}
