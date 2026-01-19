<?php

session_start();
 require_once "assets/dabco.php";
 require_once "assets/commonfunk.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    if(!only_user(dabco_insert(), $_POST['username'])){

        IF(reg_user(dabco_insert(), $_POST)){
            $_SESSION["usermessage"] = 'User registered successfully!';
        }else{
            $_SESSION["usermessage"] = 'ERROR: You are not registered!';
        }
    }else{
        $_SESSION["usermessage"] = 'ERROR';
    }

}

echo "<!doctype html>";
echo "<html>";

echo "<head>";
echo "<title>Consoles</title>";
echo "<link rel='stylesheet' href='css/styles.css'>";
echo "</head>";
echo "<body>";

echo "<div class='container'>";
echo "<h1>Consoles</h1>";
require_once 'assets/nav.php';
echo "<br>";

echo "<br>";

    echo "<div class='form-container'>";
    echo "<form method='post' action=''>";

    echo "<label for='username'>Username: </label>";
    echo "<br>";
    echo "<input type='text' name='username' placeholder='Username'>";
    echo "<br>";

    echo "<label for='password'>Password: </label>";
    echo "<br>";
    echo "<input type='password' name='password' placeholder='Password'>";
    echo "<br>";

    echo "<label for='date'>Sign up date: </label>";
    echo "<br>";
    echo "<input type='text' name='date' placeholder='sign up date'>";
    echo "<br>";

    echo "<label for='birth'>Date of birth: </label>";
    echo "<br>";
    echo "<input type='text' name='birth' placeholder='birth date'>";
    echo "<br>";

    echo "<label for='country'>Country of origin: </label>";
    echo "<br>";
    echo "<input type='text' name='country' placeholder='country'>";
    echo "<br>";

    echo "<label for='submit'>submit: </label>";
    echo "<br>";
    echo "<input type='submit' name='submit' value='Login'>";

echo "</form>";


        echo"<img src='images/switch.png' id='switch' alt='Switch'>";



        echo"<img src='images/Switch2.png' id='switch2' alt='Switch 2'>";



echo "</div>";

echo "</body>";

echo "</html>";



