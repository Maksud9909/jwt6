package com.maksudrustamov.springboot.jwt6.repository.config;

import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


// our request will be checked every time, when we will send a request
@Component // spring should see it
@RequiredArgsConstructor //
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;


    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal( @Nonnull HttpServletRequest request, // this parametrs should not to be null
                                     @Nonnull HttpServletResponse response,
                                     @Nonnull FilterChain filterChain // it contains other filters that we will need
    ) throws ServletException, IOException {

        // this place hold JWT Token, we need to pass jwt auth within the header, it is part of out request
        final String autHeader = request.getHeader("Authorization"); // it contains bearer token, our jwt is here
        final String jwt;
        final String userEmail;

        if (autHeader == null || !autHeader.startsWith("Bearer ") || autHeader.isBlank()){
            filterChain.doFilter(request,response); // we need to pass request,response to the next filter
            return; // it means if we go up to here, we do not want to continue smth in this "if"
        }
        jwt = autHeader.substring(7); // we got jwt here
        userEmail = jwtService.extractUsername(jwt);// i am getting userEmail from jwtToken from method extractUsername

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt,userDetails))
        }
    }
}











