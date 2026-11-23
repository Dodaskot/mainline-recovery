package org.a22x.contacts;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.ContentProviderOperation;
import android.content.ContentProviderResult;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.Context;
import android.database.Cursor;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.provider.ContactsContract.CommonDataKinds.Email;
import android.provider.ContactsContract.CommonDataKinds.Phone;
import android.provider.ContactsContract.CommonDataKinds.StructuredName;
import android.provider.ContactsContract.Data;
import android.provider.ContactsContract.RawContacts;
import android.telephony.PhoneNumberUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class ImportContacts extends Instrumentation {
    private static final int MAX_PAYLOAD = 32 * 1024 * 1024;
    private static final String[] DATA_COLUMNS = {Data.RAW_CONTACT_ID, Data.MIMETYPE, Data.DATA1};
    private static final String[] NAME_COLUMNS = {StructuredName.FAMILY_NAME, StructuredName.GIVEN_NAME,
        StructuredName.MIDDLE_NAME, StructuredName.PREFIX, StructuredName.SUFFIX};
    private Bundle arguments;

    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        arguments = args;
        start();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            result.putString("a22x_result", apply(getTargetContext()).toString());
            finish(Activity.RESULT_OK, result);
        } catch (Exception error) {
            result.putString("a22x_error", error.getClass().getSimpleName());
            finish(Activity.RESULT_CANCELED, result);
        }
    }

    private JSONArray input(Context context) throws Exception {
        try (InputStream file = context.openFileInput("contacts.json")) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            for (int size; (size = file.read(buffer)) != -1;) {
                if (size > MAX_PAYLOAD - bytes.size()) throw new IllegalArgumentException();
                bytes.write(buffer, 0, size);
            }
            byte[] data = bytes.toByteArray();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder hex = new StringBuilder(64);
            for (byte value : digest) hex.append(String.format(Locale.ROOT, "%02x", value & 255));
            if (!hex.toString().equals(arguments.getString("sha256"))) throw new SecurityException();
            return new JSONArray(new String(data, StandardCharsets.UTF_8));
        }
    }

    private static final class Contact {
        String name = "";
        final Set<String> phones = new HashSet<>();
        final Set<String> emails = new HashSet<>();

        void row(String mime, String value) {
            if (value == null || value.isEmpty()) return;
            if (StructuredName.CONTENT_ITEM_TYPE.equals(mime) && name.isEmpty()) {
                name = nameKey(value);
            } else if (Phone.CONTENT_ITEM_TYPE.equals(mime)) {
                String normalized = PhoneNumberUtils.normalizeNumber(value);
                phones.add(normalized.isEmpty() ? value.trim() : normalized);
            } else if (Email.CONTENT_ITEM_TYPE.equals(mime)) {
                emails.add(value.trim().toLowerCase(Locale.ROOT));
            }
        }

        boolean contains(Contact expected) {
            return name.equals(expected.name) && phones.containsAll(expected.phones) && emails.containsAll(expected.emails);
        }
    }

    private static String nameKey(String name) {
        return Normalizer.normalize(name.trim(), Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
    }

    private static Map<Long, Contact> contacts(ContentResolver resolver, Long id) {
        Map<Long, Contact> rows = new HashMap<>();
        String selection = Data.MIMETYPE + " IN (?,?,?)";
        String[] mimeTypes = {StructuredName.CONTENT_ITEM_TYPE, Phone.CONTENT_ITEM_TYPE, Email.CONTENT_ITEM_TYPE};
        String[] args = mimeTypes;
        if (id != null) {
            selection += " AND " + Data.RAW_CONTACT_ID + "=?";
            args = new String[]{mimeTypes[0], mimeTypes[1], mimeTypes[2], id.toString()};
        }
        try (Cursor cursor = resolver.query(Data.CONTENT_URI, DATA_COLUMNS, selection, args, Data._ID + " ASC")) {
            if (cursor == null) throw new IllegalStateException();
            while (cursor.moveToNext()) rows.computeIfAbsent(cursor.getLong(0), key -> new Contact())
                .row(cursor.getString(1), cursor.getString(2));
        }
        return rows;
    }

    private static ContentProviderOperation.Builder detail(String mime) {
        return ContentProviderOperation.newInsert(Data.CONTENT_URI).withValueBackReference(Data.RAW_CONTACT_ID, 0)
            .withValue(Data.MIMETYPE, mime);
    }

    private static void points(ArrayList<ContentProviderOperation> operations, Contact wanted, JSONArray values,
                               String mime, int type) throws Exception {
        for (int pos = 0; pos < values.length(); ++pos) {
            String value = values.getString(pos);
            operations.add(detail(mime).withValue(Data.DATA1, value).withValue(Data.DATA2, type).build());
            wanted.row(mime, value);
        }
    }

    private JSONObject apply(Context context) throws Exception {
        JSONArray input = input(context);
        ContentResolver resolver = context.getContentResolver();
        String accountName = RawContacts.getLocalAccountName(context);
        String accountType = RawContacts.getLocalAccountType(context);
        Map<String, List<Contact>> index = new HashMap<>();
        for (Contact row : contacts(resolver, null).values()) {
            index.computeIfAbsent(row.name, key -> new ArrayList<>()).add(row);
        }
        int inserted = 0;
        int alreadyPresent = 0;
        for (int pos = 0; pos < input.length(); ++pos) {
            JSONObject source = input.getJSONObject(pos);
            String display = source.getString("display");
            JSONArray name = source.getJSONArray("name");
            Contact wanted = new Contact();
            wanted.row(StructuredName.CONTENT_ITEM_TYPE, display);
            ArrayList<ContentProviderOperation> ops = new ArrayList<>();
            ops.add(ContentProviderOperation.newInsert(RawContacts.CONTENT_URI)
                .withValue(RawContacts.ACCOUNT_NAME, accountName).withValue(RawContacts.ACCOUNT_TYPE, accountType).build());
            // Include the local account assertion in the insert transaction. Providers may supply
            // a configured default account for unspecified values.
            ops.add(ContentProviderOperation.newAssertQuery(RawContacts.CONTENT_URI)
                .withSelection(RawContacts._ID + "=?", new String[]{"0"}).withSelectionBackReference(0, 0)
                .withValue(RawContacts.ACCOUNT_NAME, accountName).withValue(RawContacts.ACCOUNT_TYPE, accountType)
                .withExpectedCount(1).build());
            ContentProviderOperation.Builder structuredName = detail(StructuredName.CONTENT_ITEM_TYPE)
                .withValue(StructuredName.DISPLAY_NAME, display);
            for (int i = 0; i < NAME_COLUMNS.length; ++i) {
                String field = name.getString(i);
                if (!field.isEmpty()) structuredName.withValue(NAME_COLUMNS[i], field);
            }
            ops.add(structuredName.build());
            points(ops, wanted, source.getJSONArray("phones"), Phone.CONTENT_ITEM_TYPE, Phone.TYPE_OTHER);
            points(ops, wanted, source.getJSONArray("emails"), Email.CONTENT_ITEM_TYPE, Email.TYPE_OTHER);
            List<Contact> sameName = index.computeIfAbsent(wanted.name, key -> new ArrayList<>());
            if (sameName.stream().anyMatch(row -> row.contains(wanted))) {
                ++alreadyPresent;
                continue;
            }
            ContentProviderResult[] write = resolver.applyBatch(ContactsContract.AUTHORITY, ops);
            Long id = ContentUris.parseId(write[0].uri);
            Contact saved = contacts(resolver, id).get(id);
            if (saved == null || !saved.contains(wanted)) throw new IllegalStateException();
            sameName.add(saved);
            ++inserted;
        }
        return new JSONObject().put("inserted", inserted).put("already_present", alreadyPresent)
            .put("contacts", input.length()).put("verified", true);
    }
}
