import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Objects;
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws  Exception{
            auth.inMemoryAuthentication().withUser("user").password("123123")
                    .roles("USER").and().withUser("Admin").password("123321").roles("ADMIN");
    }
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeRequests().antMatchers("/").permitAll().and()
                .authorizeRequests().antMatchers("/user**").hasRole("USER").and()
                .authorizeRequests().antMatchers("/admin**").hasRole("ADMIN").and()
                .formLogin().and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
    }
}
