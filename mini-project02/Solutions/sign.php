<?php
echo"<html>";

echo"<head>";
echo"<title>GibJohn Sign in</title>";
echo"<link rel='stylesheet' href='css/style.css'>";
echo"</head>";

echo"<body>";
echo "<img id='logo' src='images/logo.jpg'  alt='logo' >";
echo"<img id='done' src='images/GoneGreat.jpg' alt='done'>";
echo"<h1>Sign in</h1>";
    echo "<form method='post' action=''>"; // Change 'login.php' to your handler script
        echo "<table>";



            echo "<tr><td>";
            echo "<label for='email'>Email or Username:</label><br>";
            echo "<input type='text' name='email' id='email' placeholder='Enter your email or username' required>";
            echo "</td></tr>";

            echo "<tr><td>";
            echo "<label for='password'>Password:</label><br>";
            echo "<input type='password' name='password' id='password' placeholder='Enter your password' required>";
            echo "</td></tr>";

            echo "<tr><td>";
            echo "<input type='submit' value='Sign In'>";
            echo "</td></tr>";

        echo "</table>";
    echo "</form>";

if($_SERVER["REQUEST_METHOD"] == "POST"){

    echo"<hr>";
    echo"<p>";
    echo"Your username or Email is: ".$_POST["email"]."<br>";
    echo"Your password is: ".$_POST["password"]."<br>";
    echo"</p>";
}
echo"<a href='index.php'>Return back</a>";
echo"</body>";
echo"</html>";

