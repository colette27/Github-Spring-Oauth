package com.coletteGit;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.json.JSONObject;

@SpringBootApplication
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {

    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {

        System.out.println(new JSONObject(principal.getAttributes()).toString());

        // String token = cookies.get("io").value

        /*
         * # ... and POST it back to GitHub   result =
         * RestClient.post('https://github.com/login/oauth/access_token',
         *                           {:client_id => CLIENT_ID,
         *                            :client_secret => CLIENT_SECRET,
         *                            :code => session_code},
         *                            :accept => :json)
         */

        Map<String, Object> ret = new HashMap<String, Object>();

        ret.put("avatar_url", principal.getAttribute("avatar_url"));

        ret.put("login", principal.getAttribute("login"));

        ret.put("bio", principal.getAttribute("bio"));

        ret.put("repos_url", principal.getAttribute("repos_url"));

        return ret;
    }

    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    // @formatter:off
    http
        .authorizeRequests(a -> a
            .antMatchers("/", "/error", "/webjars/**").permitAll()
            .anyRequest().authenticated()
        )
        .exceptionHandling(e -> e
            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        )
                .csrf(c -> c
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        )
        .logout(l -> l
        .logoutSuccessUrl("/").permitAll()
    )
    .csrf(c -> c
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
)
        .oauth2Login();
    // @formatter:on
    }

}
