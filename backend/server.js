import express from 'express';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.routes.js';
import cookieParser from 'cookie-parser';


import connectMongoDB from './db/connectMongoDB.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json({limit: '5mb'}));
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

app.get('/', (req, res) => {
  res.send('Server is ready');
});

app.use("/api/auth", authRoutes);


app.listen(PORT, ()=>{
  console.log(`Server is up and running on port ${PORT}`);
  connectMongoDB();
})