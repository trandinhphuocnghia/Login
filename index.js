const express = require('express')
const exphds = require('express-handlebars')
const session = require('express-session')
const passport = require('passport')
const localStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')
const Mongodb = require('./DB/config')
const User = require('./app/Model/User')
const app = express()
const port= 3110
const path = require('path')
const {flash} = require('express-flash-message')
//connect to Mongoose
Mongodb.connect()

//config static file
app.use(express.static(path.join(__dirname, 'public')))

//config handlebars template engine
app.engine('hbs',exphds({
    extname: '.hbs',
}))
app.set('view engine','hbs')
app.set('views',path.join(__dirname,'app/views'))



//session config
app.use(session({
    secret: "verygoodsecret",
	resave: false,
	saveUninitialized: true
}))

//urlencoded the post request
app.use(express.urlencoded({extended:false}))
app.use(express.json());

// apply express-flash-message middleware
app.use(flash({ sessionKeyName: 'flashMessage' }));

//passport
app.use(passport.initialize())
app.use(passport.session())
passport.serializeUser(function(user,done){
    done(null,user.id)
})
passport.deserializeUser(function(id,done){
  User.findById(id,function(err,user){
      done(err,user)
  })
})
passport.use(new localStrategy(function (username, password, done) {
	User.findOne({ username: username },  function (err, user) {
		if (err) return done(err);
		if (!user) return done(null, false, { message: 'Incorrect username.' });

		bcrypt.compare(password, user.password,  function (err, res) {
			if (err) return done(err);
			if (res === false) return done(null, false, { message: 'Incorrect password.' });
			
			return done(null, user);
		});
	});
}));
//
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()) return next();
    res.redirect('/Login')
    
}

function isLoggedOut(req,res,next){
    if(! req.isAuthenticated()) return next();
    res.redirect('/')
}

//routes
app.get('/',isLoggedIn,(req,res)=>{
    res.render("C:\\Users\\Login\\app\\Views\\Home.hbs",{title:"Home"});
})



app.get('/Login',isLoggedOut, (req,res)=>{
	//const messages = await req.consumeFlash('message'); 
    res.render('Login.hbs',{title:"Login"})
})

app.post('/Login',passport.authenticate('local',{
	successRedirect: '/',
	failureRedirect: '/login?error=true'
}))

app.get('/Logout', function (req, res) {
	req.logout();
	res.redirect('/');
});
//Setup or register admin
app.get('/setup', async (req, res) => {
	const exists = await User.exists({ username: "admin" });

	if (exists) {
        console.log('exists')
		res.redirect('/login');
		return;
	};

	bcrypt.genSalt(10, function (err, salt) {
		if (err) return next(err);
		bcrypt.hash("pass", salt, function (err, hash) {
			if (err) return next(err);
			
			const newAdmin = new User({
				username: "admin",
				password: hash
			});

			newAdmin.save();

			res.redirect('/Login');
		});
	});
});

app.listen(port,()=>{
    console.log(`App listening at http://localhost:${port}`) 
})



