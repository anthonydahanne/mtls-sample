/*
 * Copyright 2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.pivotal.mtlssample.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootApplication
public class ServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServerApplication.class, args);
    }

    @RestController
    static final class Server {

        private final Logger logger = LoggerFactory.getLogger(this.getClass());

        private final SerialNumberExtractor serialNumberExtractor;

        Server(SerialNumberExtractor serialNumberExtractor) {
            this.serialNumberExtractor = serialNumberExtractor;
        }

        @GetMapping("/admin")
        String admin(Principal principal) {
            String applicationId = principal.getName();
            String certificateSerialNumber = this.serialNumberExtractor.getSerialNumber(principal);

            this.logger.info("Received request for /admin with certificate for {} with SN {}", applicationId, certificateSerialNumber);
            return String.format("You authenticated using x509 certificate for %s with SN %s", applicationId, certificateSerialNumber);
        }

        @GetMapping("/")
        String user(Principal principal) {
            String applicationId = principal.getName();
            String certificateSerialNumber = this.serialNumberExtractor.getSerialNumber(principal);

            this.logger.info("Received request for / with certificate for {} with SN {}", applicationId, certificateSerialNumber);
            return String.format("You authenticated using x509 certificate for %s with SN %s", applicationId, certificateSerialNumber);
        }

    }

    @EnableWebSecurity
    static class WebSecurityConfig {

        private final List<String> adminClientIds;

        WebSecurityConfig(@Value("${mtls_admin_client_ids}") List<String> adminClientIds) {
            this.adminClientIds = adminClientIds.stream()
                .map(clientId -> String.format("%s", clientId))
                .collect(Collectors.toList());
        }

        @Bean
        public UserDetailsService userDetailsService() {
            System.out.println("UserDetailsService bean was loaded!");
            return username -> {
                User.UserBuilder builder = User.withUsername(username).password("NOT-USED");
                // careful the username comes with the OU like: OU=space:dfed3da1-8df9-4f25-a8ee-815ad2eb6969 + OU=organization:18945314-d7b4-46de-8f0f-590ab249ca1b
                String cleanupUsername = username.substring(0, username.indexOf(" "));
                builder = this.adminClientIds.contains(cleanupUsername) ? builder.roles("ADMIN", "USER") : builder.roles("USER");
                return builder.build();
            };
        }

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            // @formatter:off
            HandlerMappingIntrospector introspector = new HandlerMappingIntrospector();
            introspector.setApplicationContext(http.getSharedObject(ApplicationContext.class));
            String mvcPattern = "/admin/**";
            MvcRequestMatcher mvcRequestMatcher = new MvcRequestMatcher(introspector, mvcPattern);
            http
                .x509()
                    .subjectPrincipalRegex("OU=app:(.*?)(?:,|$)")
                    .and()
                .authorizeRequests()
                    .requestMatchers(mvcRequestMatcher).hasRole("ADMIN")
                    .anyRequest().authenticated();
            // @formatter:on
            return http.build();
        }

    }

}
