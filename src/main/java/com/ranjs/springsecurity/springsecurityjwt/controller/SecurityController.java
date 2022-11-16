package com.ranjs.springsecurity.springsecurityjwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.ranjs.springsecurity.springsecurityjwt.models.AuthenticationRequest;
import com.ranjs.springsecurity.springsecurityjwt.models.AuthenticationResponse;
import com.ranjs.springsecurity.springsecurityjwt.user.deatils.MyUserDetailsService;
import com.ranjs.springsecurity.springsecurityjwt.util.JwtTokenUtil;

@RestController
public class SecurityController {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	MyUserDetailsService myUserDetailsService;

	@Autowired
	JwtTokenUtil jwtTokenUtil;

	// to test use postman
	// localhost:800/hello --get method
	// copy jwt generated in localhost:800/authenticate
	// in authorization --select berarer token --paste jwt token and hit send --
	// will work
	// if u will remove the token -- it wont work
	// no save or same session as stateless
	@RequestMapping({ "/hello" })
	public String hello() {
		return ("Hello World");
	}

	// to test use postman --post method
	// localhost:800/authenticate and pass below value in body

//	{
//        
//        "username": "root",
//        "password":"Ranjs1993"
//
//}

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest)
			throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUserName(), authenticationRequest.getPassword()));
		} catch (BadCredentialsException e) {
			throw new Exception("Invalid username or password", e);
		}

		final UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticationRequest.getUserName());
		final String jwt = jwtTokenUtil.generateToken(userDetails);

		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

}
