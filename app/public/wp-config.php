<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * Localized language
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/ 
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'local');

/** Database username */
define('DB_USER', 'root');

/** Database password */
define('DB_PASSWORD', 'root');

/** Database hostname */
define('DB_HOST', 'localhost');

/** Database charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The database collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/  WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         'l2K]IB::3i6}N$J{&CZ1qe-=VcZ*.i3~d<?#DZBB a#JgkPz{xQW@R<|-!PWiRWH');
define('SECURE_AUTH_KEY',  '8|x94QRTE0hu>k i2or$(3caE^c7fdfC+,b$64]C=[,Y:%kCAw5o~.g<B#i2P+Zr');
define('LOGGED_IN_KEY',    '<?M&7@jd3XZ!rgVWOOV%U5S(Klld-^/M_:?p+.RJ*?HpZuM49+dn|0#X3S4pTRUN');
define('NONCE_KEY',        '+ggC0VsLA#-vY>bCGVh;8n1Gt<8vtQDtX`)9VLQA(Qrf(P|zM/+!w[G0hQq)uf>O');
define('AUTH_SALT',        'p13||3]Yd >V>q+KOpRPI#,s[~(5RR@bI$SwroA/?U?l-=U0+{0$,/x@/$<kwG&4');
define('SECURE_AUTH_SALT', 'OB Lmd(nl1O_/|&>lT-~D8nk6z>?]AOj{Nfi|A.YU@#?JT}Ue,dh!| xK~<2%|He');
define('LOGGED_IN_SALT',   '5$7f;8W]>WuvOcjE)lje|uo.7yYO2 XGymxiQFa~rUe5e); }&YD86d2kU9F-rk0');
define('NONCE_SALT',       ' c;EU&8CNr^x2&w&q%xVjT,+&Cr$qY?fD}KH;HnIPSCCsRl{&87CD])bAYD:NQn$');
define('WP_CACHE_KEY_SALT', 'yQ6bM1 obbOoul6Jdr3=?U)(.o>#x ,`W.[!7KJn{fIexndVzmt!g 4d:8Una@q.');

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**#@+
 * Debugging settings.
 *
 * Enable debugging for development environments.
 */
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
@ini_set('display_errors', 0);

/**#@-*/

/**
 * Environment type.
 */
define('WP_ENVIRONMENT_TYPE', 'local');

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';