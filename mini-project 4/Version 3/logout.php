<?php

session_start();

require_once 'assets/dabco.php';
require_once 'assets/commonfunk.php';

audititor(dabco_insert(),($_SESSION['patid'] ,"LOG",'User has been successfully logged out.' );

session_destroy();

header("Location:index.php?message=Logout Successful");

