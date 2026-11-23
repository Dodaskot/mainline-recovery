package org.a22x.migration;

import android.content.AttributionSource;
import android.content.ContentProviderOperation;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.wifi.WifiConfiguration;
import android.os.Bundle;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Process;
import android.provider.ContactsContract;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * The A22x recovery's one-time migration helper, run by the new system's one-time script as root:
 * CLASSPATH=agent.dex app_process /system/bin org.a22x.migration.Agent contacts OLD_contacts2.db
 * CLASSPATH=agent.dex app_process /system/bin org.a22x.migration.Agent wifi SSID_HEX PSK_HEX|''
 *
 * wifi (2026-11-21): a network the recovery saved, as it keeps it: the SSID in hex and the WPA key
 * as 64 hex digits (or none, open), which `cmd wifi add-network` cannot take (it quotes a
 * passphrase of 8 to 63 characters). Added as Android's own settings add one, with
 * IWifiManager.addOrUpdateNetwork, the raw key unquoted as WifiConfiguration allows.
 *
 * (A staged copy: opened for writing, as SQLite needs for a database with its write-ahead log.)
 * Contacts are read from the earlier system's contacts2.db with Android's own SQLite and inserted
 * through the new system's contacts provider (whatever provider it ships), as local contacts.
 * Only the common data kinds are carried; deleted and read-only (synced, profile) rows are not.
 *
 * The provider is reached as Android's own `content` command reaches it (2026-11-21: a system
 * context's ContentResolver was refused on Android 16, "Unable to find app for caller ... when
 * getting content provider com.android.contacts", since this process is no app the activity manager
 * knows): IActivityManager.getContentProviderExternal with a token of its own, then the provider's
 * applyBatch with this caller's attribution (root), released after.
 */
public final class Agent {
    private static final Set<String> KINDS = new HashSet<>(Arrays.asList(
            "vnd.android.cursor.item/name", "vnd.android.cursor.item/phone_v2",
            "vnd.android.cursor.item/email_v2", "vnd.android.cursor.item/postal-address_v2",
            "vnd.android.cursor.item/organization", "vnd.android.cursor.item/note",
            "vnd.android.cursor.item/nickname", "vnd.android.cursor.item/website",
            "vnd.android.cursor.item/contact_event", "vnd.android.cursor.item/im",
            "vnd.android.cursor.item/relation", "vnd.android.cursor.item/photo"));
    private static final int BATCH = 300;

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && "wifi".equals(args[0])) {
            System.out.println("wifi " + wifi(args[1], args[2]));
            return;
        }
        if (args.length != 2 || !"contacts".equals(args[0])) {
            System.err.println("usage: Agent contacts PATH | Agent wifi SSID_HEX PSK_HEX");
            System.exit(2);
        }
        try (Provider provider = new Provider(ContactsContract.AUTHORITY)) {
            System.out.println("contacts " + contacts(provider, args[1]));
        }
    }

    /** A content provider held as the `content` command holds it (frameworks/base/cmds/content). */
    static final class Provider implements AutoCloseable {
        private final Object manager, provider;
        private final String authority;
        private final IBinder token = new Binder();

        Provider(String authority) throws Exception {
            this.authority = authority;
            manager = Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
            Object holder = call(manager, "getContentProviderExternal", authority, 0, token, "a22x-migration");
            if (holder == null) throw new IllegalStateException("No provider for " + authority);
            provider = holder.getClass().getField("provider").get(holder);
        }

        void applyBatch(ArrayList<ContentProviderOperation> ops) throws Exception {
            if (Build.VERSION.SDK_INT >= 31) call(provider, "applyBatch", attribution(), authority, ops);
            else call(provider, "applyBatch", caller(), null, authority, ops);
        }

        @Override
        public void close() throws Exception {
            try {
                call(manager, "removeContentProviderExternalAsUser", authority, token, 0);
            } catch (NoSuchMethodException old) {
                call(manager, "removeContentProviderExternal", authority, token);
            }
        }

        static String caller() {
            int uid = Process.myUid();
            return uid == 0 ? "root" : uid == 2000 ? "com.android.shell" : null;
        }

        private static Object attribution() {
            return new AttributionSource.Builder(Process.myUid()).setPackageName(caller()).build();
        }

        /** The public method NAME of TARGET that takes ARGS (by count and type), invoked. */
        static Object call(Object target, String name, Object... args) throws Exception {
            for (Method method : target.getClass().getMethods()) {
                Class<?>[] types = method.getParameterTypes();
                if (!method.getName().equals(name) || types.length != args.length) continue;
                boolean fits = true;
                for (int i = 0; i < types.length && fits; i++) {
                    Class<?> type = types[i].isPrimitive() ? (types[i] == int.class ? Integer.class : types[i]) : types[i];
                    fits = args[i] == null ? !types[i].isPrimitive() : type.isInstance(args[i]);
                }
                if (!fits) continue;
                method.setAccessible(true);  // a binder proxy's class is not public
                try {
                    return method.invoke(target, args);
                } catch (InvocationTargetException error) {
                    Throwable cause = error.getCause();
                    throw cause instanceof Exception ? (Exception) cause : error;
                }
            }
            throw new NoSuchMethodException(target.getClass().getName() + "." + name + "/" + args.length);
        }
    }

    private static int wifi(String ssidHex, String psk) throws Exception {
        if (!ssidHex.matches("([0-9a-fA-F]{2}){1,32}") || !(psk.isEmpty() || psk.matches("[0-9a-fA-F]{64}"))) {
            throw new IllegalArgumentException("Invalid network");
        }
        byte[] name = new byte[ssidHex.length() / 2];
        for (int i = 0; i < name.length; i++) name[i] = (byte) Integer.parseInt(ssidHex.substring(2 * i, 2 * i + 2), 16);
        WifiConfiguration config = new WifiConfiguration();
        config.SSID = "\"" + new String(name, java.nio.charset.StandardCharsets.UTF_8) + "\"";
        int security = psk.isEmpty() ? 0 : 2;  // WifiConfiguration.SECURITY_TYPE_OPEN / SECURITY_TYPE_PSK
        try {
            WifiConfiguration.class.getMethod("setSecurityParams", int.class).invoke(config, security);
        } catch (NoSuchMethodException old) {
            config.allowedKeyManagement.set(psk.isEmpty() ? WifiConfiguration.KeyMgmt.NONE : WifiConfiguration.KeyMgmt.WPA_PSK);
        }
        if (!psk.isEmpty()) config.preSharedKey = psk.toLowerCase(java.util.Locale.ROOT);
        Object binder = Class.forName("android.os.ServiceManager").getMethod("getService", String.class).invoke(null, "wifi");
        if (binder == null) throw new IllegalStateException("No wifi service");
        Object manager = Class.forName("android.net.wifi.IWifiManager$Stub").getMethod("asInterface", IBinder.class).invoke(null, binder);
        Object id;
        try {
            id = Provider.call(manager, "addOrUpdateNetwork", config, Provider.caller(), new Bundle());
        } catch (NoSuchMethodException older) {
            id = Provider.call(manager, "addOrUpdateNetwork", config, Provider.caller());
        }
        int netId = id instanceof Integer ? (Integer) id : -1;
        if (netId < 0) throw new IllegalStateException("The network was refused");
        return netId;
    }

    private static int contacts(Provider resolver, String path) throws Exception {
        SQLiteDatabase db = SQLiteDatabase.openDatabase(path, null, SQLiteDatabase.OPEN_READWRITE);
        ArrayList<ContentProviderOperation> ops = new ArrayList<>();
        int carried = 0;
        try (Cursor raw = db.rawQuery("SELECT _id FROM raw_contacts WHERE deleted=0", null)) {
            while (raw.moveToNext()) {
                long id = raw.getLong(0);
                ArrayList<ContentValues> rows = new ArrayList<>();
                try (Cursor data = db.rawQuery("SELECT m.mimetype, d.is_primary, d.is_super_primary, d.data1, d.data2,"
                        + " d.data3, d.data4, d.data5, d.data6, d.data7, d.data8, d.data9, d.data10, d.data11, d.data12,"
                        + " d.data13, d.data14, d.data15 FROM data d JOIN mimetypes m ON d.mimetype_id = m._id"
                        + " WHERE d.raw_contact_id = ?", new String[]{Long.toString(id)})) {
                    while (data.moveToNext()) {
                        String kind = data.getString(0);
                        if (!KINDS.contains(kind)) continue;
                        ContentValues row = new ContentValues();
                        row.put(ContactsContract.Data.MIMETYPE, kind);
                        row.put(ContactsContract.Data.IS_PRIMARY, data.getInt(1));
                        row.put(ContactsContract.Data.IS_SUPER_PRIMARY, data.getInt(2));
                        for (int i = 1; i <= 15; i++) {
                            int column = i + 2;
                            if (data.isNull(column)) continue;
                            if (i == 15) row.put("data15", data.getBlob(column));
                            else row.put("data" + i, data.getString(column));
                        }
                        rows.add(row);
                    }
                }
                if (rows.isEmpty()) continue;  // a raw contact without carried data
                if (ops.size() + 1 + rows.size() > BATCH && !ops.isEmpty()) {
                    resolver.applyBatch(ops);
                    ops.clear();
                }
                int base = ops.size();
                ops.add(ContentProviderOperation.newInsert(ContactsContract.RawContacts.CONTENT_URI)
                        .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, null)
                        .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, null).build());
                for (ContentValues row : rows) {
                    ops.add(ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                            .withValues(row).withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, base).build());
                }
                carried++;
            }
        } finally {
            if (!ops.isEmpty()) resolver.applyBatch(ops);
            db.close();
        }
        return carried;
    }
}
