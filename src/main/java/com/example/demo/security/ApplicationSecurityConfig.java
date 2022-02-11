package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtSecretKey;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserRole.*;

/*Method #1 Using antMatchers*/
@Configuration
@EnableWebSecurity

/*Method #2 Using @PreAuthorize*/
@EnableGlobalMethodSecurity(prePostEnabled = true)

public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;
    private final JwtSecretKey jwtSecretKey;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService,
                                     SecretKey secretKey,
                                     JwtConfig jwtConfig, JwtSecretKey jwtSecretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
        this.jwtSecretKey = jwtSecretKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()                                                                                       /*Security by tokens*/
                .sessionManagement()                                                                                    /*Create a stateless session for*/
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))                        /*This is JSON Web Token Auth*/
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtSecretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)                   /*Adding new filter AFTER a specific filter*/
                /*  Resume
                *   This is a collections of filters that works in Request Process
                *       #1  JwtUsernamePasswordAuthenticationFilter
                *           - Validates credentials
                *           - returns a Verified Token
                *       #2  JwtTokenVerify
                *           - Check if the Token is valid or not
                *           - ifValid -> Allow access to resources
                *           - ifInvalid -> Throw Exception
                *
                *
                *
                *
                * */
                .authorizeRequests()                                                                                    /*Adding Permissions to a specific path*/
                    .antMatchers("/","index", /*"/signin",*/ "/css/*", "/js/*").permitAll()
                    .antMatchers("/api/**").hasRole(STUDENT.name())
//                  /*PERMISSIONS Method #1 Using antMatchers*/
//                  .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
//                  .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
//                  .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
//                  /*.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())   *//*We can skip HttpMethod.GET*/
//                  .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())                    /*Order of the antMatchers does matter because goes throw matches one by one in order of declarations*/
                    .anyRequest()
                    .authenticated()
//              .and()
//              .httpBasic();                                                                                           /*This is Basic Auth*/
//              .formLogin()                                                                                            /*This is Base Auth, give us a personalized login*/
//                  .loginPage("/login")                                                                                /*Reference to login page*/
//                  .permitAll()                                                                                        /*Permit to everyone can log in*/
//                  .defaultSuccessUrl("/courses", true)                                                                /*On a successful login redirect*/
//                  .usernameParameter("user")                                                                          /*Change name of param username*/
//                  .passwordParameter("pass")                                                                          /*Change name of param password*/
//              .and()
//              .rememberMe()                                                                                           /*Remember SESSIONID, default expirationTime -> 2 weeks*/
//                  .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))                                            /*Change to 21 days expirationTime SESSIONID*/
//                  .key("something_very_secure")                                                                       /*key to generate md5 of two values, username & expirationTime*/
//                  .rememberMeParameter("rememberMe")                                                                  /*Change name of param remember-me*/
//              .and()
//              .logout()                                                                                               /*Configure logout*/
//                  .logoutUrl("/logout")                                                                               /*url*/
//                  .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))                                  /*if csrf is disabled the method should be GET, else should remove that line*/
//                  .clearAuthentication(true)                                                                          /*clear credentials*/
//                  .invalidateHttpSession(true)                                                                        /*invalidate session*/
//                  .deleteCookies("JSESSIONID", "XSRF-TOKEN", "remember-me")                                           /*clear cookies*/
//                  .logoutSuccessUrl("/login");                                                                        /*Redirect to login page when got a successful log out*/
                ;
    }

    /*-------------------------------- Method #1 Used for UserService by local storage -------------------------------*/

    /*@Override
    @Bean
    protected UserDetailsService userDetailsService() {

        *//*User.UserBuilder erik = User.builder()                    *//**//*Method #1*//**//*
                .username("erik")
                .password(passwordEncoder.encode("1234 "))
                .roles("STUDENT"); *//**//*ROLE_STUDENT*//**//*

        return new InMemoryUserDetailsManager(
                erik.build()
        );*//*

        UserDetails erik = User.builder()                           *//*Method #2*//*
                .username("1")
                .password(passwordEncoder.encode("1"))
//                .roles(STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                .build(); *//*ROLE_STUDENT*//*

        UserDetails admin = User.builder()                          *//*Method #2*//*
                .username("2")
                .password(passwordEncoder.encode("1"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build(); *//*ROLE_ADMIN*//*

        UserDetails adminTrainee = User.builder()                   *//*Method #2*//*
                .username("3")
                .password(passwordEncoder.encode("1"))
//                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build(); *//*ROLE_ADMINTRAINEE*//*

        return new InMemoryUserDetailsManager(
                erik,           *//*ROLE_STUDENT*//*
                admin,          *//*ROLE_ADMIN*//*
                adminTrainee    *//*ROLE_ADMINTRAINEE*//*
        );
    }*/

    /*-------------------------- Method #2 Used for UserService by Remote Data Base Store ----------------------------*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
