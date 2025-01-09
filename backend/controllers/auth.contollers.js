import { generateTokenAndSetCookie } from "../lib/utils/generateToken.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import postmark from "postmark";



export const register = async (req, res) => {
    try {
        const {username, email, password} = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^/s@]+$/;    
        if(!emailRegex.test(email)){
            return res.status(400).json({error: "Invalid email format"});   
        }

        const existingUser = await User.findOne({username});    
        if(existingUser){
            return res.status(400).json({ error: "Username is already taken"});
        }

        const existingEmail = await User.findOne({email});
        if(existingEmail){
            return res.status(400).json({error: "Email already taken"});
        }


        if(password.length < 6){
            return res.status(400).json({error: "Password must be atleast 6 characters long"});
        }
        //hash password
        const salt = await bcrypt.genSalt(10);  
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const newUser = new User({
            username,
            email,
            password: hashedPassword, 
        })

        if(newUser){
            generateTokenAndSetCookie(newUser._id, res);
            await newUser.save();

            res.status(201).json({
                _id : newUser._id,
                username: newUser.username,
                email: newUser.email,
            })  
        }else{
            res.status(400).json({error: "Invalid user data"}); 
        }
    } catch (error) {
        console.log("Error in register controller: ", error.message);
        return res.status(500).json({error: "Internal server error"});
        
    }
}

export const login = async (req, res) => {
    try {
        const {username, password} = req.body;
        const user = await User.findOne({username});
        const isPasswordCorrect = await bcrypt.compare(password, user?.password || "");
        if(!user || !isPasswordCorrect){
            return res.status(400).json({error: "Invalid username or password"});
        }

        const token = generateTokenAndSetCookie(user._id, res);
        res.status(200).json({
            _id : user._id,
            username: user.username,
            email: user.email,
        });
    } catch (error) {
        console.log("Error in login controller: ", error.message);
        return res.status(500).json({error: "Internal server error"});
    }
}

const client = new postmark.ServerClient('87a40d69-28af-46c9-844b-63d2639dfb26');

export const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const resetToken = crypto.randomBytes(20).toString("hex");
        const resetTokenExpires = Date.now() + 3600000; // 1 hour

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = resetTokenExpires;
        await user.save();

        const resetLink = `http://localhost:5000/reset-password/${resetToken}`;

        await client.sendEmail({
            From: "imt_2022108@iiitm.ac.in",
            To: email,
            Subject: "Password Reset Link",
            TextBody: `You requested a password link. Click on the link to reset your password: ${resetLink}`,
            HtmlBody: `<p>You requested a password reset. Click the link below to reset your password:</p>
                       <a href="${resetLink}">Reset Password</a>`,
        });

        res.status(200).json({ message: `Password reset link sent to email. The reset link is ${resetLink}`  });

    } catch (error) {
        console.log("Error in forgotPassword controller: ", error.message);
        return res.status(500).json({error: "Internal server error"});
        
    }
}

export const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if(!user){
            return res.status(400).json({error: "Invalid or expired token"});
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({message: "Password reset successful"});
    } catch (error) {
        console.log("Error in resetPassword controller: ", error.message);
        return res.status(500).json({error: "Internal server error"});
        
    }
}