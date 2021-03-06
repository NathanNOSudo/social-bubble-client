import React, {useState} from "react"
import "./login.css"

export const Login = () => {
    return(
        <div className = "login-container">
            <div className = "logo">Social Bubble</div>
            <div className = "login-form">
                <div className = "username-container">
                    <label>Username</label>
                    <input className = "username-input" type = "text"></input>
                </div>
                <div className = "password-container">
                    <label>Password</label>
                    <input className = "password-input" type = "text"></input>
                </div>
               
                <button className = "signIn-button">Sign In</button>
            </div>
            <div className = "signup-link">
                <p>Not a user? Sign up here!</p>
            </div>
            
            
            
        </div>
    )
}

export default Login