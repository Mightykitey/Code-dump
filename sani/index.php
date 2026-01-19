<?php
/*session_start();/*each page not file

require_once "assets/commonfunk.php"; //require_once only happen once anywhere

if ($_SERVER["REQUEST_METHOD"] === 'POST') { // super global veurable
    // echo $_POST["message"];
    $_SESSION['msg'] = $_POST["message"];

}*/

echo"<!doctype html>";

echo"<html>";

echo"<head>";

echo"<title></title>";
echo"<link rel='css/styles.css' href='stylesheet'>";

echo"</head>";

echo"<body>";

/*echo "<div class='content'>";

echo usr_msg();*/

echo "<form method='post' action=''>";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $mge=filter_var($_POST["message"],FILTER_SANITIZE_STRING);
    echo"Your message is " .$mge;
    echo"<br>";


    $mail=filter_var($_POST["email"],FILTER_VALIDATE_EMAIL);
    echo"Your email address is " .$mail;
    echo"<br>";


    $pass=filter_var($_POST["password"],FILTER_VALIDATE_EMAIL);
    echo"Your password is " .$pass;
    echo"<br>";


    $lk=filter_var($_POST["url"],FILTER_SANITIZE_URL);
    echo"Your url is " .$lk;
    echo"<br>";


    $num=filter_var($_POST["number"],FILTER_SANITIZE_NUMBER_INT);
    echo"Your number is " .$num;
    echo"<br>";


    $dec=filter_var($_POST["float"],FILTER_SANITIZE_NUMBER_FLOAT,
        FILTER_FLAG_ALLOW_FRACTION);
    echo "Your decimal is " .$dec;
    echo"<br>";
}



echo"<br>";
echo"<Label ='message'>Please leave a message </Label>";
echo"<br>";
echo"<input type='text' name='message' id='msg' placeholder='message'>";

echo"<br>";
echo"<label ='Email'>Please enter our email </label>";
echo"<br>";
echo"<input type='text' name='email' id='email' value='email'placeholder='Email'>";

Echo"<br>";
echo"<Label='password'>Please enter your password</label>";
echo"<br>";
echo"<input type='password' name='password' id='password' placeholder='password'>";

Echo"<br>";
echo"<Label='url'>Place your URL here </label>";
echo"<br>";
echo"<input type='url' name='url' id='url' placeholder='url'>";

Echo"<br>";
echo"<Label='flaot'>Place the number </label>";
echo"<br>";
echo"<input type='text' name='number' id='number' placeholder='number'>";

echo"<br>";
echo"<label='float'>Please enter a decimal number </lable>";
echo"<br>";
echo"<input type='string' name='float' id='float' placeholder='number'>";


echo"<br>";
echo"<label='lgn'>sudmit</label>";

echo"<br>";
echo "<input  type='submit' name='submit'  value='submit'>";

echo"</body>";

echo"</html>";

?>