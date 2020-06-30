package com.lighting.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @author baikun
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.httpBasic()//开启httpbasic认证
//                .and()
//                .authorizeRequests()
//                .anyRequest()
//                .authenticated();//所有请求都需要登录认证才能访问

        http.csrf().disable() //禁用跨站csrf攻击防御，后面的章节会专门讲解
                .formLogin()
                .loginPage("/login.html")//用户未登录时，访问任何资源都转跳到该路径，即登录页面
                .loginProcessingUrl("/login")//登录表单form中action的地址，也就是处理认证请求的路径
                .usernameParameter("username")///登录表单form中用户名输入框input的name名，不修改的话默认是username
                .passwordParameter("password")//form中密码输入框input的name名，不修改的话默认是password
                .defaultSuccessUrl("/index")//登录认证成功后默认转跳的路径
                .and()
                .authorizeRequests()
                .antMatchers("/login.html","/login").permitAll()//不需要通过登录验证就可以被访问的资源路径
                .antMatchers("/biz1","/biz2") //需要对外暴露的资源路径
                .hasAnyAuthority("ROLE_user","ROLE_admin")  //user角色和admin角色都可以访问
                .antMatchers("/syslog","/sysuser")
                .hasAnyRole("admin")  //admin角色可以访问
                //.antMatchers("/syslog").hasAuthority("sys:log")
                //.antMatchers("/sysuser").hasAuthority("sys:user")
                .anyRequest().authenticated();

    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user").password("123").roles("user").build());
        manager.createUser(User.withUsername("admin").password("123").roles("admin").build());
        return manager;
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/fonts/**", "/img/**", "/js/**");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
            return NoOpPasswordEncoder.getInstance();
    }
}
