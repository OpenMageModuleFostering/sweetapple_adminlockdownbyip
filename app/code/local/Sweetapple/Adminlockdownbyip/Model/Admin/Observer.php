<?php
/**
 * Sweetapple_Adminlockdownbyip
 *
 * This module was developed by Sweet-Apple.  If you require any
 * support or have any questions please contact us at info@sweet-apple.co.uk.
 *
 * @category   Sweetapple
 * @package    Sweetapple_Adminlockdownbyip
 * @author     Clive Sweeting, Sweet-Apple <info@sweet-apple.co.uk>
 * @copyright  Copyright (c) 2013 Sweet-Apple (http://www.sweet-apple.co.uk)
 * @license    OSL v3.0
 */

/**
 * Admin observer model
 *
 * @category    Mage
 * @package     Mage_Admin
 * @author      Magento Core Team <core@magentocommerce.com>
 */
class Sweetapple_Adminlockdownbyip_Model_Admin_Observer extends Mage_Admin_Model_Observer
{
    const FLAG_NO_LOGIN = 'no-login';

    const XML_IP_LOCKDOWN_ACTIVE = 'sweetapple_admin_ip_lockdown/iplockdown/status';

    const XML_IP_LOCKDOWN_ADDRESSES = 'sweetapple_admin_ip_lockdown/iplockdown/ipaddresses';

    /**
     * Handler for controller_action_predispatch event
     *
     * @param Varien_Event_Observer $observer
     * @return boolean
     */
    public function actionPreDispatchAdmin($observer)
    {

        //Admin Login Lockdown
        $this->_validateIPAddress();

        $session = Mage::getSingleton('admin/session');
        /** @var $session Mage_Admin_Model_Session */
        $request = Mage::app()->getRequest();
        $user = $session->getUser();

        $requestedActionName = $request->getActionName();
        $openActions = array(
            'forgotpassword',
            'resetpassword',
            'resetpasswordpost',
            'logout',
            'refresh' // captcha refresh
        );
        if (in_array($requestedActionName, $openActions)) {
            $request->setDispatched(true);
        } else {
            if($user) {
                $user->reload();
            }
            if (!$user || !$user->getId()) {
                if ($request->getPost('login')) {
                    $postLogin  = $request->getPost('login');
                    $username   = isset($postLogin['username']) ? $postLogin['username'] : '';
                    $password   = isset($postLogin['password']) ? $postLogin['password'] : '';
                    $session->login($username, $password, $request);
                    $request->setPost('login', null);
                }
                if (!$request->getParam('forwarded')) {
                    if ($request->getParam('isIframe')) {
                        $request->setParam('forwarded', true)
                            ->setControllerName('index')
                            ->setActionName('deniedIframe')
                            ->setDispatched(false);
                    } elseif($request->getParam('isAjax')) {
                        $request->setParam('forwarded', true)
                            ->setControllerName('index')
                            ->setActionName('deniedJson')
                            ->setDispatched(false);
                    } else {
                        $request->setParam('forwarded', true)
                            ->setRouteName('adminhtml')
                            ->setControllerName('index')
                            ->setActionName('login')
                            ->setDispatched(false);
                    }
                    return false;
                }
            }
        }

        $session->refreshAcl();
    }


    private function _validateIPAddress()
    {
        $active = Mage::getStoreConfig(self::XML_IP_LOCKDOWN_ACTIVE);
        if($active){
            //Kill any requests not from whilelisted IPs
            $ipAddress = $_SERVER['REMOTE_ADDR'];
            $allowedIPAddresses = explode(',',Mage::getStoreConfig(self::XML_IP_LOCKDOWN_ADDRESSES) );
            $allowedIPAddresses = array_map('trim', $allowedIPAddresses);
            if( !in_array($ipAddress, $allowedIPAddresses)){
                print "Access Denied";
                exit;
            }
        }
        return true;
    }

}
