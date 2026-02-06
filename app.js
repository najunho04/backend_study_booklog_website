const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken'); // JWT 라이브러리 추가
const cookieParser = require('cookie-parser'); // 1. 쿠키 파서 불러오기
const path = require('path');
const app = express();
require('dotenv').config();


// 미들웨어 설정 (데이터 해석 및 정적 파일 제공)
app.use(express.json()); //json 파일로 res, req 얻기
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // 'public' 폴더의 html 파일을 브라우저에 보여줌
app.use(cookieParser()); // 2. 쿠키 파서 미들웨어 등록 (req.cookies 사용 가능)

// 서버만 알고 있어야 하는 비밀키 (실무에선 환경변수에 숨깁니다)
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET; // Refresh Token용 열쇠 (이거 추가!)

// DB 연결 설정 (Connection Pool)
// pool로 연결 시 동시다발 호출에 대응 가능
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,      // 본인 MySQL 아이디
    password: process.env.DB_PASS, // 본인 MySQL 비번
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
});


// [API] 회원가입 요청 처리 (POST)
app.post('/signup', async (req, res) => {
    // 프론트에서 보낸 데이터 받기 
    const { name, user_id, password } = req.body;
    console.log("signup", "signup...");

    try {
        const sql = `INSERT INTO users (name, user_id, password) VALUES (?, ?, ?)`;
        await pool.execute(sql, [name, user_id, password]);

        console.log("INSERT", "INSERT...");
        
        // 성공 시 응답
        res.json({ success: true, message: '회원가입 성공!' });
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: '에러 발생: ' + err.message });
    }
});

// [API] 로그인 및 JWT 발급
app.post('/login', async (req, res) => {
    const { user_id, password } = req.body;

    try {
        // DB에서 유저 확인 (실제로는 비밀번호 암호화 비교가 필요함)
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE user_id = ? AND password = ?', 
            [user_id, password]
        );

        if (rows.length > 0) {
            const user = rows[0];
            
            // JWT 생성 (페이로드에 ID와 이름을 담음)
            // 유효기간은 1시간(1h)으로 설정
            const token = jwt.sign(
                { id: user.user_id, name: user.name }, 
                JWT_SECRET, 
                { expiresIn: '1m' }
            );

            //refreshToken으로 JWT 만료 시 DB에서 유저 인증 후 JWT 재발급
            const refreshToken = jwt.sign({ id: user.user_id }, REFRESH_SECRET, { expiresIn: '14d' });

            // INSERT가 아니라 UPDATE로 기존 유저 정보에 토큰 저장
            const updateSql = `UPDATE users SET refresh_token = ? WHERE user_id = ?`;
            await pool.execute(updateSql, [refreshToken, user.user_id]);

            // 4. Refresh Token은 쿠키에 담아서 전송 (보안 설정 중요!)
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true, // 자바스크립트로 접근 불가 (XSS 방지)
                secure: false,  // HTTPS 환경이라면 true로 변경
                maxAge: 14 * 24 * 60 * 60 * 1000 // 14일 (밀리초 단위)
            });

            res.json({ success: true, token }); // 브라우저에게 토큰 전달
        } else {
            res.status(401).json({ success: false, message: '아이디 또는 비번이 틀림' });
        }
    } catch (err) {
        console.error("로그인 에러 상세:", err); // 터미널에 에러 내용 출력
        res.status(500).json({ message: '서버 에러' });
    }
});

//JWT 재발급 로직
app.get('/refresh', async (req, res) => {
    // 1. 브라우저가 자동으로 보낸 쿠키에서 Refresh Token 꺼내기
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) return res.status(401).json({ message: "리프레시 토큰 없음" });

    try{
         // 2. DB에 이 토큰이 존재하는지 확인 (중요!)
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE refresh_token = ?', 
            [refreshToken]
        );
        const user = rows[0];

        if(!user){
            return res.status(403).json({ message: "유효하지 않은 리프레시 토큰" });
        }

        console.log("user", user);

        // 3. 토큰 검증
        jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
            if (err) return res.status(403).json({ message: "리프레시 토큰 만료" });

            // 4. 새로운 Access Token 발급
            const token = jwt.sign(
                { id: user.user_id, name: user.name  },
                 JWT_SECRET,
                { expiresIn: '1m' }
            );

            console.log("token", token);
            res.json({ success: true, token }); // 브라우저에게 토큰 전달
        });

    }catch(error) {
        console.error("로그인 에러 상세:", err); // 터미널에 에러 내용 출력
        res.status(500).json({ message: '서버 에러' });
    }
});

// [미들웨어] JWT 검증 함수 (필터 역할)
// get-user-info 로직에서 req는 단 1개임. 
// 따라서 미들웨어(authenticateToken)에서 req.user 데이터를 넣어줌

// get-user-info 로직에 통합할 수도 있지만 모든 로직에서 JWT 인증을 확인해야 하기에 기능을 
// 나눔.
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN" 형식에서 토큰만 추출

    if (!token) return res.sendStatus(401); // 토큰 없으면 거절

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // 토큰이 변조되었거나 만료되면 거절
        req.user = user; // 토큰에 담긴 유저 정보를 req 객체에 넣어줌 -> 여기서 user은 payload에 담긴 user information
        next(); // 다음 로직(API)으로 진행
    });
};

// [API] 보호된 유저 정보 호출 (검증 미들웨어 사용)
app.get('/get-user-info', authenticateToken, (req, res) => {
    // authenticateToken이 성공하면 req.user에 토큰 내용이 들어있음
    res.json({ message: "인증 성공!", user: req.user });
});

// ---------------------------------------------------------
// [신규] 비회원(게스트) 입장 로직 (쿠키 사용)
// ---------------------------------------------------------
app.get('/guest-entry', (req, res) => {
    // 1. 브라우저가 보내온 쿠키 중에 'guestId'가 있는지 확인
    let guestId = req.cookies.guestId;

    // 2. 쿠키가 없다면? (처음 온 손님) -> 새로운 게스트 ID 발급
    if(!guestId){
        guestId = 'Guest_' + Math.floor(Math.random() * 100000); // 예: Guest_58291

        // 3. ""서버가 브라우저에게 "이 쿠키 저장해!" 라고 명령 (응답 헤더 설정) -> 브라우저 내부 보관소에 쿠키 저장"""
        // maxAge: 24시간(밀리초), httpOnly: 자바스크립트로 접근 불가하게 설정 (보안 강화)
        // 실무에선 httpOnly: true를 권장하지만, 클라이언트 JS에서 document.cookie로 확인해보시라고 false로 둡니다.
        res.cookie('guestId', guestId, { maxAge: 24 * 60 * 60 * 1000, httpOnly: false });
    }

    // 3. 게스트 정보 반환
    res.json({
        type: 'guest', 
        message: "비회원 입장", 
        user: { name: guestId, id: '비회원' } 
    });

});

// ---------------------------------------------------------
// 다운로드 링크 제공!
// ---------------------------------------------------------
app.post('/request-download', authenticateToken, async (req, res)=> {
    const { email } = req.body;
    const user = req.user;
    const userId = user.id;

    if (!email) {
        return res.status(400).json({ success: false, message: '이메일이 누락되었습니다.' });
    }

    try {
        const updateSql = `UPDATE users SET email = ? WHERE user_id = ?`;
        const [result] = await pool.execute(updateSql, [email, userId]);

        // 영향받은 행이 없다면 유저가 없는 것
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: '유저를 찾을 수 없습니다.' });
        }
        
        res.json({ success: true, message: "이메일 업데이트 및 다운로드 요청 완료" });
    } catch (err) {
        console.error("다운로드 에러 상세:", err); // 터미널에 에러 내용 출력
        res.status(500).json({ message: '서버 에러' });
    }
});

// 서버 실행 
app.listen(3000, () => {
    console.log('🚀 서버가 3000번 포트에서 실행 중입니다: http://localhost:3000');
});

// 첫 html 파일 세팅
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});