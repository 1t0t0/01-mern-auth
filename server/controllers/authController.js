import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js'; 
import transporter from '../config/nodemailer.js';


//register-section
export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: 'Missing Detail' });
    }

    try {
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({ success: false, message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign(
            { id: user._id }, // ใส่ id ของผู้ใช้ใน token
            process.env.JWT_SECRET, // ใช้ secret จาก environment variable
            { expiresIn: '7d' } // Token หมดอายุใน 7 วัน
        );

        res.cookie('token', token, {
            httpOnly: true, // ป้องกัน cookie จากการเข้าถึงผ่าน JavaScript ฝั่ง client
            secure: process.env.NODE_ENV === 'production', // ใช้ HTTPS ใน production
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', // ป้องกัน cookie ถูกส่งข้ามโดเมน
            maxAge: 7 * 24 * 60 * 60 * 1000, // อายุ cookie 7 วัน
        });

        //Sending welcome email
        const mailOption = {
            from:process.env.SENDER_EMAIL,
            to:email,
            subject:"Welcome to New member 🎉",
            text:`Welcome come to our website. Your account has been created with email id:${email}`
        }
        await transporter.sendMail(mailOption)


        return res.json({ success: true});

        

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
};


//login-section
export const login = async (req,res) => {
    const {email,password} = req.body;

    if(!email || !password){
        return res.json({success:false,message:'Email and password are required'})
    }

    try{

        const user = await userModel.findOne({email})

        if(!user){
            return res.json({success:false,message:"Invalid email"})
        }

        const isMatch = await bcrypt.compare(password,user.password);

        if(!isMatch){
            return res.json({success:false,message:"Invalid password"})
        }

        const token = jwt.sign(
            { id: user._id }, 
            process.env.JWT_SECRET,
            { expiresIn: '7d' } 
        );

        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', 
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.json({success:true});

    }catch(error) {
        return res.json({success:false,message:error.message})

    }

}


//logout-section
export const logout = async(req,res) =>{
    try{
        res.clearCookie('token',{
            httpOnly: true, // ป้องกัน cookie จากการเข้าถึงผ่าน JavaScript ฝั่ง client
            secure: process.env.NODE_ENV === 'production', // ใช้ HTTPS ใน production
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', // ป้องกัน cookie ถูกส่งข้ามโดเมน
        })
        return res.json({success:true,message:"Logged Out"})
    }catch(error){
        return res.json({success:false,message:error.message})
    }
}

//Send Verification OTP to the User's Email
export const sendVerifyOtp = async(req,res)=>{
    try{
        const {userId} = req.body;

        const user = await userModel.findById(userId)

        if(user.isAccountVerified){
            return res.json({success:false,message:"Account Already verified"})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000) ) ;

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

        await user.save();

        const mailOption = {
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:"Account Verification OTP",
            text:`Your OTP is ${otp}. Verify your account using this OTP`
        }
        await transporter.sendMail(mailOption)

        return res.json({success:true,message:"Verification OTP Sent on Email"})


    }catch(error){
        res.json({success:false,message:error.message})
    }
}

// 
export const verifyEmail = async (req,res) => {
    const {userId,otp} = req.body

    if(!userId || !otp){
        return res.json({success:false,message:"Missing Details"})
    }

    try{
        const user = await userModel.findById(userId)

if(!user){
    return res.json({success:false,message:"User not found"})
}

if(user.verifyOtp === '' || user.verifyOtp !== otp){
    return res.json({success:false,message:"Invalid OTP"})
}

if(user.verifyOtpExpireAt < Date.now()){
    return res.json({success:false,message:'OTP Expired'})
}

user.isAccountVerified = true;
user.verifyOtp = '';
user.verifyOtpExpireAt = 0

await user.save();
return res.json({success:true,message:'Email verified successfully'})

    }catch(error){
        return res.json({success:false,message:error.message})
    }
}