<?php

echo"<!doctype html>";

echo"<html>";
echo"<head>";

echo"<title>Password Rat3r1!</title>";
echo "<link rel='stylesheet' href='css/styles.css'>";
echo"</head>";

    echo"<body>";

        echo"<h1>Password Rater</h1>";
        require_once 'assets/nav.php';
        echo"<br>";

        echo"<div class='content'>";
            echo"<h2>Why using different passwords are important</h2>";
                echo"<p> Using different passwords for each account is important because it protects you from 
                         hackers who try stolen passwords on multiple sites—a tactic called credential stuffing. 
                         If you reuse the same password and one account is breached, all your other accounts become vulnerable too. 
                         Unique passwords limit the damage of a breach, help prevent identity theft, and keep your sensitive information safe. 
                         Using a password manager makes it easy to generate and store strong, unique passwords without needing to remember them all.
                    </p>";
        echo"</div>";

        echo"<br>";
        echo"<br>";

        echo"<div class='content'>";
            echo"<h2>Why should we change are password frequency</h2>";
                echo"<p> You should change your password regularly to protect your personal information from unauthorized access. 
                 Over time, passwords can become compromised through data breaches, phishing attacks, or simply by being reused across multiple accounts. 
                 By updating your password frequently and using strong, unique combinations, you reduce the risk of identity theft and keep your online accounts more secure.
            </p>";

        echo"</div>";

    echo"</body>";

echo"</html>";

?>