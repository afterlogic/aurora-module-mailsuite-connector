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
	
	/**
	 * 
	 * @param string $Email
	 * @param string $Hash
	 */
	protected function sendRegisterNotification($Email, $Hash)
	{
		$oSettings =& \Aurora\System\Api::GetSettings();
		$sSiteName = $oSettings->GetConf('SiteName');
		$sBody = \file_get_contents($this->GetPath().'/templates/RegistrationMail.html');
		$oMail = new \PHPMailer();
		
		if (\is_string($sBody)) 
		{
			$sBody = \strtr($sBody, array(
				'{{INVITATION_URL}}' => \rtrim($this->oHttp->GetFullUrl(), '\\/ ') . "/index.php?registration/" . $Hash,
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
		
		$sSubject = "You're registered to join " . $sSiteName;
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
		}
		
		return $mResult;
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
            \Aurora\System\Api::$__SKIP_CHECK_USER_ROLE__ = true;
            \Aurora\System\Api::Location('/change-password.html?h=' . $sHash);

            \Aurora\System\Api::$__SKIP_CHECK_USER_ROLE__ = false;
        }
        else
        {
            return 'This link is expired';
        }
    }


    protected function getUserByResetEmail($ResetEmail) {
        $oCoreModule = \Aurora\System\Api::GetModule('Core');
        if ($oCoreModule instanceof \Aurora\System\Module\AbstractModule) {
            $oUserManager = $oCoreModule->oApiUsersManager;

            $oUser = null;
            if (!empty($oUserManager)) {

                /* @var $oUserManager \Aurora\Modules\Core\Managers\Users */
                $aUsers = $oUserManager->getUserList(0, 1, null, null, null,['MailSuiteConnector::ResetEmail' => [$ResetEmail, '=']]);

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
     * @return bool
     * @throws \Aurora\System\Exceptions\ApiException
     */
    public function onResetPassword($aArgs, &$mResult)
    {
        \Aurora\System\Api::$__SKIP_CHECK_USER_ROLE__ = true;
        $ResetEmail = empty($aArgs['ResetEmail']) ? null : $aArgs['ResetEmail'];

        $mResult = false;

        if (!empty(\trim($ResetEmail)) && \filter_var($ResetEmail, FILTER_VALIDATE_EMAIL))
        {
            $oUser = $this->getUserByResetEmail($ResetEmail);

            if (!empty($oUser)) {
                $sPasswordResetHash = $this->generateHash($oUser->EntityId, __FUNCTION__);
                $oUser->PasswordResetHash = $sPasswordResetHash;
                \Aurora\Modules\Core\Module::Decorator()->UpdateUserObject($oUser);
                $mResult = $this->sendResetPasswordNotification($ResetEmail, $sPasswordResetHash);

            }
        }
        else
        {
            throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
        }

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
        \Aurora\System\Api::$__SKIP_CHECK_USER_ROLE__ = true;

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

        if (!empty($oUser) && !empty($oAccount->IncomingPassword) && ($oAccount->IncomingPassword !== $sPassword))
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
        $bInterrupt = false;

        $oAccount = \Aurora\Modules\Mail\Module::Decorator()->GetAccount($aArguments['AccountId']);

        $mResult = $this->сhangePassword($oAccount, $aArguments['NewPassword']);

        if ($mResult === true)
        {
            $bInterrupt = true;
        }

        return $bInterrupt;
    }

	/***** private functions *****/
	
	/***** public functions *****/
	public function Register($FirstName, $LastName, $Email, $Password, $ConfirmPassword, $ResetEmail)
	{
		$mResult = false;
		\Aurora\System\Api::$__SKIP_CHECK_USER_ROLE__ = true;
		if ($Password === $ConfirmPassword && !empty(\trim($Password)) && !empty(\trim($Email)) && !empty(\trim($ResetEmail)) &&
				\filter_var($Email, FILTER_VALIDATE_EMAIL) && \filter_var($ResetEmail, FILTER_VALIDATE_EMAIL))
		{
			$iUserId = \Aurora\Modules\Core\Module::Decorator()->CreateUser(0, $Email);
			$oUser = \Aurora\Modules\Core\Module::Decorator()->GetUser($iUserId);

			$oUser->{$this->GetName() . '::FirstName'} = $FirstName;
			$oUser->{$this->GetName() . '::LastName'} = $LastName;
			$oUser->{$this->GetName() . '::Email'} = $Email;
			$oUser->{$this->GetName() . '::Password'} = $Password;
			$oUser->{$this->GetName() . '::ResetEmail'} = $ResetEmail;
			
			\Aurora\Modules\Core\Module::Decorator()->UpdateUserObject($oUser);
			
			$mResult = $this->sendRegisterNotification($ResetEmail, $this->generateHash($iUserId));
			if (!$mResult)
			{
				\Aurora\Modules\Core\Module::Decorator()->DeleteUser($iUserId);
			}
		}
		else
		{
			throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::InvalidInputParameter);
		}
		
		\Aurora\System\Api::$__SKIP_CHECK_USER_ROLE__ = false;
		
		return $mResult;
    }

	
	/***** public functions might be called with web API *****/
}
