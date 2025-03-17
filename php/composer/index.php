<?php

require 'vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use PHPMailer\PHPMailer\PHPMailer;
use GuzzleHttp\Client;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Doctrine\ORM\EntityManager;

class VulnerableDemo
{
    public function demonstrateVulnerabilities()
    {
        $request = Request::createFromGlobals();
        $response = new Response('Content');
        $response->setVary(['Accept-Encoding']);
        $response->setCache([
            'max_age' => 3600,
            'public' => true,
        ]);

        $mail = new PHPMailer(true);
        try {
            $mail->setFrom('attacker@example.com>', 'Attacker');
            $mail->addAddress('victim@example.com');
            $mail->Subject = 'Test Subject';
            $mail->Body = 'Test Body';
            $mail->send();
        } catch (Exception $e) {
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }

        $client = new Client();
        $userInput = 'http://internal-service/api';
        try {
            $response = $client->request('GET', $userInput, [
                'allow_redirects' => true
            ]);
        } catch (Exception $e) {
            echo $e->getMessage();
        }

        $log = new Logger('vulnerable_logger');
        $log->pushHandler(new StreamHandler('logs/app.log', Logger::DEBUG));
        $log->info('Sensitive information', [
            'password' => 'secret123',
            'api_key' => 'ak_live_123456789'
        ]);

        $userInput = "admin' OR '1'='1";
        $dql = "SELECT u FROM User u WHERE u.username = '" . $userInput . "'";
    }
}

$demo = new VulnerableDemo();
$demo->demonstrateVulnerabilities(); 