<?php
/**
 * @copyright Copyright (c) 2017, Afterlogic Corp.
 * @license AGPL-3.0 or AfterLogic Software License
 *
 * This code is licensed under AGPLv3 license or AfterLogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\MailSuiteConnector;
use Aurora\Modules\Mail\Exceptions\Exception;

/**
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractModule
{
	protected $sMailSuiteRESTApiUrl = "";
	protected $sToken = null;
	protected $sEmailToDelete = "";
	
	/***** private functions *****/
	/**
	 * Initializes Module.
	 * 
	 * @ignore
	 */
	public function init() 
	{
		$this->sMailSuiteRESTApiUrl = $this->getConfig('MailSuiteRESTApiUrl', null);
		$this->subscribeEvent('Mail::CreateAccount::before', array($this, 'onBeforeCreateAccount'));
		$this->subscribeEvent('Mail::DeleteAccount::before', array($this, 'onBeforeDeleteAccount'));
        $this->subscribeEvent('Core::ResetPassword', array($this, 'onResetPassword'));
        $this->subscribeEvent('Core::ResetPasswordBySecurityQuestion', array($this, 'onResetPasswordBySecurityQuestion'));
        $this->subscribeEvent('Core::UpdatePassword', array($this, 'onUpdatePassword'));
        $this->subscribeEvent('Mail::ChangePassword::before', array($this, 'onBeforeChangePassword'));
		
		$this->extendObject(
			'Aurora\Modules\Core\Classes\User', 
			array(
				'FirstName' => array('string', ''),
				'LastName' => array('string', ''),
				'Email' => array('string', ''),
				'Password' => array('encrypted', ''),
				'ResetEmail' => array('string', ''),
				'Hash' => array('string', '')
			)
		);
		
		$this->AddEntry('registration', 'EntryRegistration');
        $this->AddEntry('change_password', 'EntryChangePassword');
	}
	
	protected function sendAction($sMethod, $sAction, $aArguments)
	{
		$mResult = null;
		if (isset($this->sMailSuiteRESTApiUrl))
		{
			$sUrl = $this->sMailSuiteRESTApiUrl . $sAction;
			$curl = curl_init();
			curl_setopt_array($curl, array(
			  CURLOPT_URL => $sUrl . '?'.http_build_query($aArguments),
			  CURLOPT_CUSTOMREQUEST => $sMethod,
			  CURLOPT_SSL_VERIFYPEER => false,
			  CURLOPT_RETURNTRANSFER => true
			));
			$mResult = curl_exec($curl);
			curl_close($curl);				
		}
		return $mResult;
	}

	protected function getToken()
	{
		if (!isset($this->sToken))
		{
			if (isset($this->sMailSuiteRESTApiUrl))
			{
				$sResult = $this->sendAction("GET", "/token", array(
					'login' => $this->getConfig('MailSuiteAdminLogin'),
					'password' => $this->getConfig('MailSuiteAdminPassword')
				));
				if (isset($sResult))
				{
					$oResult = json_decode($sResult);
					if (!isset($oResult->errorCode) && isset($oResult->result))
					{
						$this->sToken = $oResult->result;
					}
				}
			}
		}
		
		return $this->sToken;
	}

    protected function sendResetPasswordNotification($Email, $Hash)
    {
        $oSettings =& \Aurora\System\Api::GetSettings();
        $sSiteName = $oSettings->GetConf('SiteName');
        $sBody = \file_get_contents($this->GetPath().'/templates/ResetPasswordMail.html');
        $oMail = new \PHPMailer();

        if (\is_string($sBody))
        {
            $sBody = \strtr($sBody, array(
                '{{RESET_PASSWORD_URL}}' => \rtrim($this->oHttp->GetFullUrl(), '\\/ ') . "/index.php?change_password/" . $Hash,
                '{{SITE_NAME}}' => $sSiteName
            ));

            $sBody = preg_replace_callback(
                "/[\w\-]*\.png/Uim",
                function ($matches) use ($oMail) {
                    $sResult = $matches[0];

                    if (\file_exists($this->GetPath().'/templates/'.$matches[0]))
                    {
                        $sContentId = \preg_replace("/\.\w*/", "", $matches[0]);

                        $oMail->AddEmbeddedImage($this->GetPath().'/templates/'.$matches[0], $sContentId);
                        $sResult = "cid:".$sContentId;
                    }

                    return $sResult;
                },
                $sBody
            );
        }

        $sSubject = 'Reset your password';
        $sFrom = $this->getConfig('NotificationEmail', '');

        $sType = $this->getConfig('NotificationType', 'mail');
        if (\strtolower($sType) === 'mail')
        {
            $oMail->isMail();
        }
        else if (\strtolower($sType) === 'smtp')
        {
            $oMail->isSMTP();
            $oMail->Host = $this->getConfig('NotificationHost', '');
            $oMail->Port = 25;
            $oMail->SMTPAuth = (bool) $this->getConfig('NotificationUseAuth', false);
            if ($oMail->SMTPAuth)
            {
                $oMail->Username = $this->getConfig('NotificationLogin', '');
                $oMail->Password = $this->getConfig('NotificationPassword', '');
            }
            $oMail->SMTPOptions = array(
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true
                )
            );
        }

        $oMail->setFrom($sFrom);
        $oMail->addAddress($Email);
        $oMail->addReplyTo($sFrom, $sSiteName);

        $oMail->Subject = $sSubject;
        $oMail->Body    = $sBody;
        $oMail->isHTML(true);                                  // Set email format to HTML

        try {
            $mResult = $oMail->send();
        } catch (\Exception $oEx){
            throw new \Exception('Failed to send notification. Reason: ' . $oEx->getMessage());
        }

        return $mResult;
    }

	protected function getMinId($iUserId, $sSalt = '')
	{
		return \implode('|', array($this->GetName(), $iUserId, \md5($iUserId), $sSalt));
	}
	
	protected function generateHash($iUserId, $sSalt = '')
	{

		$mHash = '';
		$oMin = \Aurora\Modules\Min\Module::Decorator();
		if ($oMin)
		{
			$sMinId = $this->getMinId($iUserId, $sSalt);
			$mHash = $oMin->GetMinByID($sMinId);
			
			
			if (!$mHash)
			{
				$mHash = $oMin->CreateMin(
					$sMinId,
					array(
						'UserId' => $iUserId
					)
				);
			}
			else
			{
				if (isset($mHash['__hash__']))
				{
					$mHash = $mHash['__hash__'];
				}
				else
				{
					$mHash = '';
				}
			}
		}
		
		return $mHash;
	}
	
	protected function getUserByHash($sHash)
	{
		$oUser = null;
		$oMin = \Aurora\Modules\Min\Module::Decorator();
		if ($oMin)
		{
			$mHash = $oMin->GetMinByHash($sHash);
			if (isset($mHash['__hash__'], $mHash['UserId']))
			{
				$iUserId = $mHash['UserId'];
				$oCore = \Aurora\Modules\Core\Module::Decorator();
				if ($oCore)
				{
					$oUser = $oCore->GetUser($iUserId);
				}
			}
		}
		return $oUser;
	}	
	
	/**
	 * @ignore
	 */
	public function onBeforeCreateAccount($aArgs, $mResult)
	{
		if (isset($this->sMailSuiteRESTApiUrl))
		{
			$sResult = $this->sendAction("POST", "/account", array(
				'token' => $this->getToken(),
				'email' => $aArgs["IncomingLogin"],
				'password' => $aArgs["IncomingPassword"]
			));
		}
	}
	
	public function onBeforeDeleteAccount($aArgs, $mResult)
	{
		$oMailDecorator = \Aurora\System\Api::GetModuleDecorator('Mail');
		
		$oAccount = $oMailDecorator->GetAccount($aArgs['AccountID']);
		if ($oAccount)
		{
			$sResult = $this->sendAction("DELETE", "/account", array(
				'token' => $this->getToken(),
				'email' => $oAccount->IncomingLogin,
			));
		}
	}
	
	public function EntryRegistration()
	{
		$sHash = (string) \Aurora\System\Application::GetPathItemByIndex(1, '');
		$oUser = $this->getUserByHash($sHash);
		$sErrorCode = '';
		if ($oUser)
		{
			$oMailDecorator = \Aurora\System\Api::GetModuleDecorator('Mail');

			try
			{
				\Aurora\System\Api::skipCheckUserRole(true);
				$mResult = $oMailDecorator->CreateAccount(
					$oUser->EntityId, 
					$oUser->{$this->GetName() . '::FirstName'} . ' ' . $oUser->{$this->GetName() . '::LastName'}, 
					$oUser->{$this->GetName() . '::Email'}, 
					$oUser->{$this->GetName() . '::Email'}, 
					$oUser->{$this->GetName() . '::Password'}
				);
				\Aurora\System\Api::skipCheckUserRole(false);

				$oCoreDecorator = \Aurora\System\Api::GetModuleDecorator('Core');
				\Aurora\System\Api::skipCheckUserRole(true);
				$mResult = $oCoreDecorator->Login($oUser->{$this->GetName() . '::Email'}, $oUser->{$this->GetName() . '::Password'});
				\Aurora\System\Api::skipCheckUserRole(false);
			}
			catch(\Exception $oEx)
			{
				\Aurora\System\Api::Location('/login.html');
			}
			
			if (is_array($mResult) && isset($mResult['AuthToken']))
			{
				$oUser->resetToDefault($this->GetName() . '::Password');
				$oMin = \Aurora\Modules\Min\Module::Decorator();
				if ($oMin)
				{
					$sMinId = $this->getMinId($oUser->EntityId);				
					\Aurora\System\Api::skipCheckUserRole(true);
					$oMin->DeleteMinByID($sMinId);
					\Aurora\System\Api::skipCheckUserRole(false);
				}
				
				@setcookie('AuthToken', $mResult['AuthToken'], time() + 60 * 60 * 24 * 30);
			}
			\Aurora\System\Api::Location('./');
		}
		else
		{
			\Aurora\System\Api::Location('/login.html');
		}
	}

    public function EntryChangePassword()
    {

        $sHash = (string) \Aurora\System\Application::GetPathItemByIndex(1, '');
        $oUser = $this->getUserByHash($sHash);

        if ($oUser)
        {
			$bPrevState =  \Aurora\System\Api::skipCheckUserRole(true);
            \Aurora\System\Api::Location('/change-password.html?h=' . $sHash);
			\Aurora\System\Api::skipCheckUserRole($bPrevState);
        }
        else
        {
            return 'This link is expired';
        }
    }


    protected function getUserByEmail($Email) {
        $oCoreModule = \Aurora\System\Api::GetModule('Core');
        if ($oCoreModule instanceof \Aurora\System\Module\AbstractModule) {
            $oUserManager = $oCoreModule->oApiUsersManager;

            $oUser = null;
            if (!empty($oUserManager)) {

                /* @var $oUserManager \Aurora\Modules\Core\Managers\Users */
                $aUsers = $oUserManager->getUserList(0, 1, null, null, null,[$this->GetName() . '::Email' => [$Email, '=']]);

                $oUser = reset($aUsers);
                if (!empty($oUser)) {
                    $oUser = $oUserManager->getUser($oUser->EntityId);
                }

            }

            return $oUser;
        }
        return false;
    }

    /**
     * @param $aArgs
     * @param $mResult
     * @return array|bool
     * @throws \Aurora\System\Exceptions\ApiException
     * @throws \Exception
     */
    public function onResetPassword($aArgs, &$mResult)
    {
		$bPrevState =  \Aurora\System\Api::skipCheckUserRole(true);
        $sEmail = empty($aArgs['email']) ? null : $aArgs['email'];
        $sResetOption = empty($aArgs['resetOption']) ? null : $aArgs['resetOption'];

        $mResult = false;
        if (!empty(\trim($sEmail)) && \filter_var($sEmail, FILTER_VALIDATE_EMAIL))
        {
            $oUser = $this->getUserByEmail($sEmail);

            if (!empty($oUser)) {

                switch($sResetOption) {
                    case 'reset_email':
                        $sPasswordResetHash = $this->generateHash($oUser->EntityId, __FUNCTION__);
                        $oUser->PasswordResetHash = $sPasswordResetHash;
                        \Aurora\Modules\Core\Module::Decorator()->UpdateUserObject($oUser);

                        $sResetEmail = $oUser->{$this->GetName() . '::ResetEmail'};
                        if  (!empty($sResetEmail)) {
                            $mResult = $this->sendResetPasswordNotification($sResetEmail, $sPasswordResetHash);
                        } else {
                            throw new \Exception('Reset email is not found for user');
                        }
                        break;
                    case 'security_question':
                        $sSecurityQuestion = $oUser->{$this->GetName() . '::SecurityQuestion'};
                        if (empty($sSecurityQuestion)) {
                            throw new \Exception('Security question is not set');
                        }
                        $mResult = [
                            'securityQuestion' => $sSecurityQuestion,
                            'securityToken' => $this->generateHash($oUser->EntityId, __FUNCTION__ . 'SecurityQuestion')
                        ];
                        break;
                    default:
                        throw new \Exception('Unknown reset option');
                        break;
                }


            }
        }
        else
        {
            throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
        }
		\Aurora\System\Api::skipCheckUserRole($bPrevState);

        return $mResult;
    }

    public function onResetPasswordBySecurityQuestion($aArgs, &$mResult)
    {
		$bPrevState =  \Aurora\System\Api::skipCheckUserRole(true);
        $sSecurityAnswer = empty($aArgs['securityAnswer']) ? null : $aArgs['securityAnswer'];
        $sSecurityToken = empty($aArgs['securityToken']) ? null : $aArgs['securityToken'];
        $oUser = $this->getUserByHash($sSecurityToken);

        $mResult = false;

        if (!empty($oUser) && !empty($sSecurityAnswer)) {
            //Check answer
            $sRightAnswer = $oUser->{$this->GetName() . '::SecurityAnswer'};

            if ($sRightAnswer === $sSecurityAnswer) {

                $sPasswordResetHash = $this->generateHash($oUser->EntityId, __FUNCTION__);
                $oUser->PasswordResetHash = $sPasswordResetHash;
                \Aurora\Modules\Core\Module::Decorator()->UpdateUserObject($oUser);

                $mResult = [
                    'passwordResetLink' => \rtrim($this->oHttp->GetFullUrl(), '\\/ ') . "/index.php?change_password/" . $sPasswordResetHash
                ];
            } else {
                throw new \Exception('Wrong answer');
            }
        } else {
            throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
        }

		\Aurora\System\Api::skipCheckUserRole($bPrevState);
        return $mResult;
    }


    /**
     *
     * @param $aArgs
     * @param $mResult
     * @return bool
     * @throws \Aurora\System\Exceptions\ApiException
     */
    public function onUpdatePassword($aArgs, &$mResult)
    {
		$bPrevState =  \Aurora\System\Api::skipCheckUserRole(true);

        $oMail = \Aurora\Modules\Mail\Module::Decorator();
        $oMin = \Aurora\Modules\Min\Module::Decorator();

        $sPassword = empty($aArgs['Password']) ? null : \trim($aArgs['Password']);
        $sConfirmPassword = empty($aArgs['ConfirmPassword']) ? null : \trim($aArgs['ConfirmPassword']);
        $sHash = empty($aArgs['Hash']) ? null : \trim($aArgs['Hash']);
        $oUser = $this->getUserByHash($sHash);

        $mResult = false;
        $oAccount = null;
        if (!empty($oMail) && !empty($oUser)) {
            $aAccounts = $oMail->GetAccounts($oUser->EntityId);
            $oAccount = reset($aAccounts);
        }


        if (!empty($oUser) && !empty($oAccount) && ($sPassword === $sConfirmPassword) && !empty($sPassword))
        {
            $mResult = $this->сhangePassword($oAccount, $sPassword);
            if ($mResult && !empty($oMin) && !empty($sHash)) {
                $oMin->DeleteMinByHash($sHash);
            }
        }
        else
        {
            throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
        }

		\Aurora\System\Api::skipCheckUserRole($bPrevState);
        return $mResult;
    }

    protected function сhangePassword($oAccount, $sPassword)
    {
        $bResult = false;

        $oCore = \Aurora\Modules\Core\Module::Decorator();
        if ($oCore)
        {
            $oUser = $oCore->GetUser($oAccount->IdUser);
        }

        if (!empty($oUser) && !empty($oAccount->IncomingPassword))
        {
            $sToken = $this->getToken();

            if (!empty($sToken) && isset($this->sMailSuiteRESTApiUrl))
            {
                try
                {
                    $sResult = $this->sendAction("PUT", "/account/password", array(
                        'token' => $sToken,
                        'email' => $oAccount->Email,
                        'password' => $sPassword
                    ));


                    if (!empty($sResult))
                    {
                        $oResult = json_decode($sResult);
                        if (!empty($oResult->errorCode))
                        {
                            throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::CanNotChangePassword);
                        } else {
                            //Update password in DB
                            $oUser->{$this->GetName() . '::Password'} = $sPassword;
                            $oUser->resetToDefault('PasswordResetHash');

                            $bResult = \Aurora\Modules\Core\Module::Decorator()->UpdateUserObject($oUser);
                        }


                    }

                }
                catch (Exception $oException)
                {
                    throw $oException;
                }
            }
            else
            {
                throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Exceptions\Errs::UserManager_AccountNewPasswordUpdateError);
            }
        }

        return $bResult;
    }

    public function onBeforeChangePassword($aArguments, &$mResult)
    {
        $oAccount = \Aurora\Modules\Mail\Module::Decorator()->GetAccount($aArguments['AccountId']);

        $mResult = $this->сhangePassword($oAccount, $aArguments['NewPassword']);
    }


    protected function sendWelcomeMail($Email)
    {
        $oSettings =& \Aurora\System\Api::GetSettings();
        $sSiteName = $oSettings->GetConf('SiteName');
        $sBody = \file_get_contents($this->GetPath().'/templates/WelcomeMail.html');
        $oMail = new \PHPMailer();

        if (\is_string($sBody))
        {
            $sBody = \strtr($sBody, array(
                '{{SITE_NAME}}' => $sSiteName
            ));

            $sBody = preg_replace_callback(
                "/[\w\-]*\.png/Uim",
                function ($matches) use ($oMail) {
                    $sResult = $matches[0];

                    if (\file_exists($this->GetPath().'/templates/'.$matches[0]))
                    {
                        $sContentId = \preg_replace("/\.\w*/", "", $matches[0]);

                        $oMail->AddEmbeddedImage($this->GetPath().'/templates/'.$matches[0], $sContentId);
                        $sResult = "cid:".$sContentId;
                    }

                    return $sResult;
                },
                $sBody
            );
        }

        $sSubject = "Welcome to " . $sSiteName;
        $sFrom = 'Foldercrate Support <support@foldercrate.org>';

        $sType = $this->getConfig('NotificationType', 'mail');
        if (\strtolower($sType) === 'mail')
        {
            $oMail->isMail();
        }
        else if (\strtolower($sType) === 'smtp')
        {
            $oMail->isSMTP();
            $oMail->Host = $this->getConfig('NotificationHost', '');
            $oMail->Port = 25;
            $oMail->SMTPAuth = (bool) $this->getConfig('NotificationUseAuth', false);
            if ($oMail->SMTPAuth)
            {
                $oMail->Username = $this->getConfig('NotificationLogin', '');
                $oMail->Password = $this->getConfig('NotificationPassword', '');
            }
            $oMail->SMTPOptions = array(
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true
                )
            );
        }

        $oMail->setFrom($sFrom);
        $oMail->addAddress($Email);
        $oMail->addReplyTo($sFrom, $sSiteName);

        $oMail->Subject = $sSubject;
        $oMail->Body    = $sBody;
        $oMail->isHTML(true);                                  // Set email format to HTML

        try {
            $mResult = $oMail->send();
        } catch (\Exception $oEx){
        }

        return $mResult;
    }

	/***** private functions *****/
	
	/***** public functions *****/
	public function Register($FirstName, $LastName, $AccountLanguage, $Email, $Password, $ConfirmPassword, $ResetEmail, $SecurityQuestion, $SecurityAnswer)
	{
		$mResult = false;
		$bPrevState =  \Aurora\System\Api::skipCheckUserRole(true);

		$ologinBlackListDecorator = \Aurora\System\Api::GetModuleDecorator('LoginBlacklist');

        $sLogin = substr($Email, 0, strpos($Email, '@'));

		$passwordIsValid            = !empty(\trim($Password)) && ($Password === $ConfirmPassword);
		$loginIsBlackListed         = $ologinBlackListDecorator->LoginIsBlacklisted($sLogin);

		if ($loginIsBlackListed) {
            throw new \Exception('Login is blacklisted', 1001);
        }

		$loginIsValid               = !empty($sLogin) && !$loginIsBlackListed;
		$emailIsValid               = !empty(\trim($Email)) && \filter_var($Email, FILTER_VALIDATE_EMAIL);
		$resetEmailIsValid          = !empty(\trim($ResetEmail)) && \filter_var($ResetEmail, FILTER_VALIDATE_EMAIL);
		$securityQuestionIsValid    = !empty($SecurityQuestion) && !empty($SecurityAnswer);



		if ($passwordIsValid && $loginIsValid && $emailIsValid && ($resetEmailIsValid || $securityQuestionIsValid))
		{
			$iUserId = \Aurora\Modules\Core\Module::Decorator()->CreateUser(0, $Email);
			$oUser = \Aurora\Modules\Core\Module::Decorator()->GetUser($iUserId);

			$oUser->{$this->GetName() . '::FirstName'} = $FirstName;
			$oUser->{$this->GetName() . '::LastName'} = $LastName;
			$oUser->{$this->GetName() . '::Email'} = $Email;
			$oUser->{$this->GetName() . '::Password'} = $Password;
			$oUser->{$this->GetName() . '::ResetEmail'} = $ResetEmail;
            $oUser->{$this->GetName() . '::SecurityQuestion'} = $SecurityQuestion;
            $oUser->{$this->GetName() . '::SecurityAnswer'} = $SecurityAnswer;

            if (!empty($AccountLanguage)) {
                $oUser->Language = $AccountLanguage;
            }
			
			\Aurora\Modules\Core\Module::Decorator()->UpdateUserObject($oUser);

            $oMailDecorator = \Aurora\System\Api::GetModuleDecorator('Mail');

            try
            {
                $mResult = $oMailDecorator->CreateAccount(
                    $oUser->EntityId,
                    $oUser->{$this->GetName() . '::FirstName'} . ' ' . $oUser->{$this->GetName() . '::LastName'},
                    $oUser->{$this->GetName() . '::Email'},
                    $oUser->{$this->GetName() . '::Email'},
                    $oUser->{$this->GetName() . '::Password'}
                );

                $oCoreDecorator = \Aurora\System\Api::GetModuleDecorator('Core');
                $bPrevState = \Aurora\System\Api::skipCheckUserRole(true);
                $mResult = $oCoreDecorator->Login($oUser->{$this->GetName() . '::Email'}, $oUser->{$this->GetName() . '::Password'});
                //Add sample data

                //Welcome mail
                $this->sendWelcomeMail($Email);

                //Contacts:
                $oContactsDecorator = \Aurora\Modules\Contacts\Module::Decorator();
                $aContactData = [
                    'FullName'          => 'Foldercrate Support',
                    'BusinessEmail'     => 'support@foldercrate.org',
                    'PrimaryEmail'      => \Aurora\Modules\Contacts\Enums\PrimaryEmail::Business,
                    'BusinessCompany'   => 'Foldercrate',
                    'BusinessCity'      => 'Solothurn',
                    'BusinessState'     => 'Solothurn',
                    'BusinessZip'       => '4500',
                    'BusinessCountry'   => 'Switzerland',
                    'BusinessPhone'     => '+41 079 738 00 98',
                    'BusinessWeb'       => 'https://foldercrate.com'
                ];
                $oContactsDecorator->CreateContact($aContactData, $oUser->EntityId);
                \Aurora\System\Api::skipCheckUserRole($bPrevState);
            }
            catch(\Exception $oEx)
            {
                $mResult = false;
            }

            if (is_array($mResult) && isset($mResult['AuthToken']))
            {
                $oUser->resetToDefault($this->GetName() . '::Password');

                @setcookie('AuthToken', $mResult['AuthToken'], time() + 60 * 60 * 24 * 30);
            }

			if (!$mResult)
			{
				\Aurora\Modules\Core\Module::Decorator()->DeleteUser($iUserId);
			}
		}
		else
		{
			throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
		}
		
		\Aurora\System\Api::skipCheckUserRole($bPrevState);
		
		return $mResult;
    }

	
	/***** public functions might be called with web API *****/
}
