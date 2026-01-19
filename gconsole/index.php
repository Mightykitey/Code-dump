<?php

if(!isset($_GET['message'])) {
    session_start();
    $message = false;
}else{
    $message = htmlspecialchars(urldecode($_GET['message']));
}



require_once "assets/dabco.php";
require_once "assets/commonfunk.php";

echo"<!doctype html>";
echo"<html>";

echo"<head>";
    echo"<title>Consoles</title>";
echo "<link rel='stylesheet' href='css/styles.css'>";

echo"</head>";

echo"<body>";

    echo"<div class='container'>";
        echo"<h1>Consoles</h1>";
        require_once 'assets/nav.php';
        echo"<br>";

    try{
        $conn = dabco_insert();
        echo "Connected successfully";
    }catch(PDOException $e){
        echo $e->getMessage();
    }


        echo"<div class='gallery'>";

            echo"<figure>";
                echo"<img src='images/Dreamcast.png' alt='Dreamcast'>";
                echo"<figcaption>The Dreamcast</figcaption>";
            echo"</figure>";

            echo "<figure>";
                echo "<img src='images/3DS.png' alt='3DS'>";
                echo "<figcaption>The 3DS</figcaption>";
            echo "</figure>";

            echo"<figure>";
                echo"<img src='images/Playstation5.png' alt='Playstation 5'>";
                echo"<figcaption>The Playstation 5</figcaption>";
            echo"</figure>";

            echo"<figure>";
                echo"<img src='images/switch.png' alt='Switch'>";
                echo"<figcaption>The Switch</figcaption>";
            echo"</figure>";

            echo"<figure>";
                echo"<img src='images/Switch2.png' alt='Switch 2'>";
                echo"<figcaption>The Switch 2</figcaption>";
            echo"</figure>";

            echo"<figure>";
                echo"<img src='images/XboxX.png' alt='XboxX'>";
                echo"<figcaption>The XboxX</figcaption>";
            echo"</figure>";

            if(!$message){
                echo user_message();
            }else{
                echo$message;
            }


        echo"</div>";
    echo"</div>";

echo"</body>";

echo"</html>";

